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

	"github.com/golang-jwt/jwt"
	"github.com/gomodule/oauth1/oauth"
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

type jwtCustomClaims struct {
	AccessToken  string `json:"access_token"`  // Token Key for Twitter
	AccessSecret string `json:"access_secret"` // Secret Key for Twitter
	jwt.StandardClaims
}

type OAuth struct {
	client oauth.Client
}

// User user info
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

type AuthURLResponse struct {
	JwtToken string `json:"jwt_token"`
	URL      string `json:"url"`
}

// --------
// JWT Config↓
// --------

var signingKey = []byte(os.Getenv("SIGNINGKEY"))

// JwtConfig ...
var JwtConfig = middleware.JWTConfig{
	SigningKey: signingKey,
	Claims:     &jwtCustomClaims{}, // カスタムClaims構造体 ※デフォルトはjwt.MapClaims{}
	ContextKey: "jwt_token",        // カスタムContextKey ※デフォルトは "user"
}

// --------
// router↓
// --------

// InitRouting ...
func InitRouting(e *echo.Echo, o *OAuth) {
	auth := e.Group("/auth")
	auth.Use(middleware.JWTWithConfig(JwtConfig))

	e.POST("/signup", o.Signup)
	auth.GET("/twitter/callback", o.TwitterCallback)
	auth.GET("/private", Private)
}

// Signup ...
func (o *OAuth) Signup(c echo.Context) error {
	loginInfo := &LoginInfo{}

	if err := c.Bind(loginInfo); err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}

	// 存在チェック（実際は、DBからUIDに対応するログイン情報を取得し、その有無で登録済みかどうかを判断するイメージ）
	if loginInfo.UID == "example@gmil.com" && loginInfo.Password == "password" {
		log.Printf("Redirect URL: %s", "/login")
		return c.Redirect(http.StatusFound, "/login") // 登録済みユーザーの場合はログインページにリダイレクト
	}

	// get twitter Access Token and Access Secret
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

	// Set custom claims
	claims := &jwtCustomClaims{
		AccessToken:  credentials.Token,
		AccessSecret: credentials.Secret,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte(os.Getenv("SIGNINGKEY")))
	if err != nil {
		log.Printf("SIGNINGKEY:%v\n", os.Getenv("SIGNINGKEY"))
		return err
	}

	return c.JSON(http.StatusOK, AuthURLResponse{JwtToken: t, URL: o.client.AuthorizationURL(credentials, nil)})
}

func (o *OAuth) TwitterCallback(c echo.Context) error {
	jwtToken := c.Get(JwtConfig.ContextKey).(*jwt.Token)
	claims := jwtToken.Claims.(*jwtCustomClaims)

	credentials := &oauth.Credentials{
		Token:  claims.AccessToken,
		Secret: claims.AccessSecret,
	}

	// 認可後にリダイレクトURL（Callback URL）に含まれるoauth_verifierパラメータが、事前に取得したAccessTokenと一致するかを確認
	if credentials.Token != c.QueryParam("oauth_token") {
		log.Printf("credentials.Token: %v\n", credentials.Token)
		return c.JSON(http.StatusInternalServerError, "invalid credentials.Token")
	}

	// get access credentials
	accessCredentials, _, err := o.client.RequestToken(nil, credentials, c.QueryParam("oauth_verifier"))
	if err != nil {
		log.Println("faild with o.client.RequestToken()")
		return c.JSON(http.StatusInternalServerError, err.Error())
	}

	// get twitter account info
	user, err := o.GetUserInfo(accessCredentials)
	if err != nil {
		log.Println("faild with GetUserInfo()")
		return c.JSON(http.StatusInternalServerError, err.Error())
	}

	// generate wtitter account url
	user.URL = "https://twitter.com/" + user.ScreenName

	// set signed flalg
	user.IsSignedIn = true

	claims.Id = user.ID

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte(os.Getenv("SIGNINGKEY")))
	if err != nil {
		log.Printf("SIGNINGKEY:%v\n", os.Getenv("SIGNINGKEY"))
		return err
	}

	log.Printf("Redirect URL: %s", "/mypage?"+t+"")
	return c.Redirect(http.StatusFound, "/mypage?"+t+"") // signup後の遷移先にリダイレクト ※ もしかしたらリダイレクトの場合、Bearerも送られるかもなのでその場合はtoken用のパラメータは不要かも
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

// Private ログイン後のみアクセス可能なPrivateメソッド
func Private(c echo.Context) error {
	user := c.Get("claims").(*jwt.Token)
	claims := user.Claims.(*jwtCustomClaims)
	return c.String(http.StatusOK, fmt.Sprintf("AccessToken:%v, AccessSecret:%v", claims.AccessToken, claims.AccessSecret))
}

// --------
// middleware↓
// --------

func InitMiddleware(e *echo.Echo) {
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
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
	e := echo.New()

	InitMiddleware(e)

	InitRouting(e, NewOAuth())

	e.Start(":8555")
}
