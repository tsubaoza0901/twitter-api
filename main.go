package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/gomodule/oauth1/oauth"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// --------
// model↓
// --------

// LoginInfo ...
type LoginInfo struct {
	UID      string `json:"uid"`
	Password string `json:"password"`
}

// type jwtCustomClaims struct {
// 	AccessToken  string `json:"access_token"`  // Token Key for Twitter
// 	AccessSecret string `json:"access_secret"` // Secret Key for Twitter
// 	jwt.StandardClaims
// }

// OAuth ...
type OAuth struct {
	client oauth.Client
}

// User user info of Twitter
type User struct {
	ID          string     `gorm:"primary_key;not null" json:"id_str"`
	ScreenName  string     `gorm:"not null" json:"screen_name"`
	Name        string     `gorm:"not null" json:"name"`
	URL         string     `gorm:"not null" json:"url"`
	Description string     `gorm:"null" json:"description"`
	IsSignedIn  bool       `gorm:"not null" json:"is_signed_in"`
	CreatedAt   time.Time  `gorm:"null" json:"create_at"`
	UpdatedAt   time.Time  `gorm:"null" json:"update_at"`
	DeletedAt   *time.Time `gorm:"null" json:"-"`
}

// AuthURLResponse ...
type AuthURLResponse struct {
	// JwtToken string `json:"jwt_token"`
	URL      string `json:"url"`
}

// // --------
// // JWT Config↓
// // --------

// var signingKey = []byte(os.Getenv("SIGNINGKEY"))

// // JwtConfig ...
// var JwtConfig = middleware.JWTConfig{
// 	SigningKey: signingKey,
// 	Claims:     &jwtCustomClaims{}, // カスタムClaims構造体 ※デフォルトはjwt.MapClaims{}
// 	ContextKey: "jwt_token",        // カスタムContextKey ※デフォルトは "user"
// }

// --------
// router↓
// --------

// InitRouting ...
func InitRouting(e *echo.Echo, o *OAuth) {
	// auth := e.Group("/auth")
	// auth.Use(middleware.JWTWithConfig(JwtConfig))

	e.GET("/signup", o.Signup)
	e.GET("/twitter/callback", o.TwitterCallback)
	e.GET("/auth_token", AuthToken)
}

// Signup ...
func (o *OAuth) Signup(c echo.Context) error {
	// loginInfo := &LoginInfo{}

	// if err := c.Bind(loginInfo); err != nil {
	// 	return c.JSON(http.StatusInternalServerError, err.Error())
	// }

	// // 存在チェック（実際は、DBからUIDに対応するログイン情報を取得し、その有無で登録済みかどうかを判断するイメージ）
	// if loginInfo.UID == "example@gmil.com" && loginInfo.Password == "password" {
	// 	log.Printf("Redirect URL: %s", "/login")
	// 	return c.Redirect(http.StatusFound, "/login") // 登録済みユーザーの場合はログインページにリダイレクト
	// }

	// get Temporary Credentials(Access Token and Secret)
	credentials, err := o.client.RequestTemporaryCredentials(
		nil,
		os.Getenv("CALLBACK_URL"), // Twitterに登録したCallback URL（認可完了後のリダイレクト時に、TwitterCallbackメソッドを呼び出すためのURL）
		nil,
	)
	if err != nil {
		log.Println("failed with client.RequestTemporaryCredentials()")
		log.Println(os.Getenv("CALLBACK_URL"))
		return c.JSON(http.StatusInternalServerError, err.Error())
	}

	sess, err := session.Get("session_name", c)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "failed to session.Get()")
	}

	if !sess.IsNew {
		// 何かしらチェック？
	}

	// set options
    sess.Options = &sessions.Options{
        Path:     "/",
		// Domain: "localhost:3999",
        MaxAge:   30, // session時間は30秒
        HttpOnly: true,
		// Secure: true,
		// SameSite: http.SameSiteNoneMode,
    }

	// set values
	sess.Values["accessToken"] = credentials.Token
	sess.Values["accessSecret"] = credentials.Secret


	// save session
    if err := sess.Save(c.Request(), c.Response()); err != nil {
		return c.JSON(http.StatusInternalServerError, "failed to sess.Save()")
	}

	res := AuthURLResponse{
		URL: o.client.AuthorizationURL(credentials, nil),
	}

	return c.JSON(http.StatusOK, res)
}

func (o *OAuth) TwitterCallback(c echo.Context) error {
	sess, err := session.Get("session_name", c)
	if err != nil {
		log.Printf("err:%v", err)
		return c.JSON(http.StatusInternalServerError, "failed to session.Get()")
	}

	if sess.IsNew {
		fmt.Printf("session:%+v", *sess)
		return c.JSON(http.StatusInternalServerError, "session is new")
	}

	credentials := &oauth.Credentials{
		Token: sess.Values["accessToken"].(string),
		Secret: sess.Values["accessSecret"].(string),
	}

	// 認可後にリダイレクトURL（Callback URL）に含まれるoauth_verifierパラメータが事前に取得したAccessTokenと一致するかを確認
	if credentials.Token != c.QueryParam("oauth_token") {
		log.Printf("credentials.Token: %v\n", credentials.Token)
		return c.JSON(http.StatusInternalServerError, "invalid credentials.Token")
	}

	// get Credentials(Access Token and Secret)
	accessCredentials, _, err := o.client.RequestToken(nil, credentials, c.QueryParam("oauth_verifier"))
	if err != nil {
		log.Println("faild with o.client.RequestToken()")
		return c.JSON(http.StatusInternalServerError, err.Error())
	}

	// get twitter account info
	twitterUserInfo, err := o.GetUserInfo(accessCredentials)
	if err != nil {
		log.Println("faild with GetUserInfo()")
		return c.JSON(http.StatusInternalServerError, err.Error())
	}

	if _, err := FetchUserByID(twitterUserInfo.ID); err != nil {
		if err != gorm.ErrRecordNotFound {
			log.Println("faild with FetchUserByID()")
			return c.JSON(http.StatusInternalServerError, err.Error())
		}

		// generate wtitter account url
		twitterUserInfo.URL = "https://twitter.com/" + twitterUserInfo.ScreenName

		// set signed flag
		twitterUserInfo.IsSignedIn = true

		if err := SaveUser(&twitterUserInfo); err != nil {
			log.Println("faild with SaveUser()")
			return c.JSON(http.StatusInternalServerError, err.Error())
		}

		// claims.Id = twitterUserInfo.ID

		// Create token with claims
		// token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		// // Generate encoded token and send it as response.
		// t, err := token.SignedString([]byte(os.Getenv("SIGNINGKEY")))
		// if err != nil {
		// 	log.Printf("SIGNINGKEY:%v\n", os.Getenv("SIGNINGKEY"))
		// 	return err
		// }
		// return c.Redirect(http.StatusFound, "/auth_token?id="+twitterUserInfo.ID+"")
		return c.Redirect(http.StatusFound, "http://localhost:3999/profiles?id="+twitterUserInfo.ID+"")
	}

	// claims.Id = twitterUserInfo.ID

	// // Create token with claims
	// token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// // Generate encoded token and send it as response.
	// t, err := token.SignedString([]byte(os.Getenv("SIGNINGKEY")))
	// if err != nil {
	// 	log.Printf("SIGNINGKEY:%v\n", os.Getenv("SIGNINGKEY"))
	// 	return err
	// }

	// return c.Redirect(http.StatusFound, "/auth_token?id="+twitterUserInfo.ID+"")
	return c.Redirect(http.StatusFound, "http://localhost:3999/top?id="+twitterUserInfo.ID+"")
}

// GetUserInfo get twitter user info
func (o *OAuth) GetUserInfo(credentials *oauth.Credentials) (User, error) {
	var user User

	err := o.APIGet(
		credentials,
		"https://api.twitter.com/1.1/account/verify_credentials.json", // ユーザー情報取得のためのリソースURL ※詳細はこちら → http://westplain.sakuraweb.com/translate/twitter/Documentation/REST-APIs/Public-API/GET-account-verify_credentials.cgi
		url.Values{"include_entities": {"true"}},
		&user,
	)
	if err != nil {
		return user, err
	}

	return user, nil
}

// APIGet call get twitter api
func (o *OAuth) APIGet(cred *oauth.Credentials, urlStr string, form url.Values, data interface{}) error {
	resp, err := o.client.Get(nil, cred, urlStr, form)
	if err != nil {
		log.Println("o.client.Get()")
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, data)
}

func decodeResponse(resp *http.Response, data interface{}) error {
	if resp.StatusCode != http.StatusOK {
		p, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("get %s returned status %d, %s", resp.Request.URL, resp.StatusCode, p)
	}
	return json.NewDecoder(resp.Body).Decode(data)
}

func FetchUserByID(id string) (*User, error) {
	user := &User{}
	if err := db.Debug().Where("id = ?", id).First(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func SaveUser(user *User) error {
	if err := db.Debug().Create(user).Error; err != nil {
		return err
	}
	return nil
}

func AuthToken(c echo.Context) error {
	id := c.QueryParam("id")

	// TODO:UsersテーブルからTwitterIDをキーにデータを取得して、取得できたらTokenを発行してtopページにリダイレクト、取得できない（未登録）の場合にはuser登録画面へ

	// UsersテーブルにTwitterIDをキーに取得できるレコードがあるか？
	// ①ある（ユーザー登録済み）
	// Tokenを発行し、topページへ

	// ②ない（ユーザー未登録）
	// Twitterから取得して保存したテーブルの情報を取得し、レスポンスで返す？

	// if token != c.QueryParam("token") {
	// 	log.Printf("token: %v\n", token)
	// 	return c.JSON(http.StatusInternalServerError, "invalid credentials.Token")
	// }

	return c.JSON(http.StatusOK, "This is Mypage, id: "+id+"")
}

// --------
// db↓
// --------

var db *gorm.DB

// InitDB ...
func InitDB() *gorm.DB {
	dsn := "root:root@tcp(db:3306)/twitterapisample?parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	return db
}

// --------
// middleware↓
// --------

func InitMiddleware(e *echo.Echo) {
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(session.Middleware(sessions.NewCookieStore([]byte(os.Getenv("SECRET")))))
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
		AllowHeaders:     []string{echo.HeaderAccessControlAllowHeaders, echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
		AllowCredentials: true,
	}))
}

// --------
// main↓
// --------

func NewOAuth() *OAuth {
	return &OAuth{
		client: oauth.Client{
			TemporaryCredentialRequestURI: "https://api.twitter.com/oauth/request_token",
			ResourceOwnerAuthorizationURI: "https://api.twitter.com/oauth/authorize",
			TokenRequestURI:               "https://api.twitter.com/oauth/access_token",
			Credentials: oauth.Credentials{
				Token:  os.Getenv("CREDENTIAL_TOKEN"),
				Secret: os.Getenv("CREDENTIAL_SECRET"),
			},
		},
	}
}

func main() {
	db = InitDB()

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatal(err)
	}
	defer sqlDB.Close()

	e := echo.New()

	InitMiddleware(e)

	InitRouting(e, NewOAuth())

	e.Start(":8555")
}
