# twitter-api

# 使用方法

## 1．Docker イメージのビルド&コンテナの起動

※実行前に、「その他」の項目を実施する必要あり

```
$ docker-compose up -d --build
```

## 2．データベースの作成

① DB コンテナ内へ移動

```
$ docker exec -it twitter-api-sample-db bash
```

② DB 接続

```
root@ec19d85976f4:/# mysql -u root -h db -p
Enter password:
```

③ DB 作成

```
mysql> CREATE DATABASE twitterapisample;
```

## 3．マイグレーションファイルの実行

① アプリケーションコンテナ内へ移動

```
$ docker exec -it twitter-api-sample bash
```

② マイグレーションファイルの実行

```
root@fe385569a625:/go/src/app# goose up
```

## 4．アプリケーションの起動

```
root@fe385569a625:/go/src/app# go run main.go
```

## その他

・dockerのビルド前に「.env」ファイルを作成し、以下の内容を設定する必要あり

```
SIGNINGKEY=任意の文字列
CREDENTIAL_TOKEN=TwitterのDeveloper用API Key
CREDENTIAL_SECRET=TwitterのDeveloper用API Secret
CALLBACK_URL=TwitterのDeveloperPortalページで登録したCallback URL

```


# エンドポイント

## 1．/signin
### ＜Request＞

POST http://127.0.0.1:8555/signup

```
{
    "uid": "任意の文字列",
    "password": "任意の文字列" 
}
```

### ＜Response＞

```
{
    "jwt_token": "eeeeee.hhhhhh.AAAAAAAa",
    "url": "https://api.twitter.com/oauth/authorize?oauth_token=ttt"
}
```

【補足】

このレポジトリを使用した front 側の実装を行う場合、上記 Response に含まれる url にアクセスする処理を行う必要あり。なお、その際、url にアクセスする際の Authorization Bearer Token に、同じく上記 Response にある jwt_token の内容を設定する。

## 2．/twitter/callback
認可レスポンス用のため使用不可