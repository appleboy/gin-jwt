# Gin JWT 中介軟體

[English](README.md) | [繁體中文](README.zh-TW.md) | [简体中文](README.zh-CN.md)

[![Run Tests](https://github.com/appleboy/gin-jwt/actions/workflows/go.yml/badge.svg)](https://github.com/appleboy/gin-jwt/actions/workflows/go.yml)
[![GitHub tag](https://img.shields.io/github/tag/appleboy/gin-jwt.svg)](https://github.com/appleboy/gin-jwt/releases)
[![GoDoc](https://godoc.org/github.com/appleboy/gin-jwt?status.svg)](https://godoc.org/github.com/appleboy/gin-jwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/appleboy/gin-jwt)](https://goreportcard.com/report/github.com/appleboy/gin-jwt)
[![codecov](https://codecov.io/gh/appleboy/gin-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/appleboy/gin-jwt)
[![codebeat badge](https://codebeat.co/badges/c4015f07-df23-4c7c-95ba-9193a12e14b1)](https://codebeat.co/projects/github-com-appleboy-gin-jwt)
[![Sourcegraph](https://sourcegraph.com/github.com/appleboy/gin-jwt/-/badge.svg)](https://sourcegraph.com/github.com/appleboy/gin-jwt?badge)

一個強大且靈活的 [Gin](https://github.com/gin-gonic/gin) Web 框架的 JWT 驗證中介軟體，基於 [jwt-go](https://github.com/golang-jwt/jwt) 實作。  
輕鬆為你的 Gin 應用程式加入登入、Token 更新與授權功能。

---

## 目錄

- [Gin JWT 中介軟體](#gin-jwt-中介軟體)
  - [目錄](#目錄)
  - [功能特色](#功能特色)
  - [安全性注意事項](#安全性注意事項)
  - [安裝](#安裝)
    - [使用 Go Modules（推薦）](#使用-go-modules推薦)
  - [快速開始範例](#快速開始範例)
  - [Demo](#demo)
    - [登入](#登入)
    - [刷新 Token](#刷新-token)
    - [Hello World](#hello-world)
    - [授權範例](#授權範例)
  - [Cookie Token](#cookie-token)
    - [登入流程（LoginHandler）](#登入流程loginhandler)
    - [需要 JWT Token 的端點（MiddlewareFunc）](#需要-jwt-token-的端點middlewarefunc)
    - [登出流程（LogoutHandler）](#登出流程logouthandler)
    - [刷新流程（RefreshHandler）](#刷新流程refreshhandler)
    - [登入失敗、Token 錯誤或權限不足](#登入失敗token-錯誤或權限不足)
  - [截圖](#截圖)
  - [授權](#授權)

---

## 功能特色

- 🔒 為 Gin 提供簡單的 JWT 驗證
- 🔁 內建登入、刷新、登出處理器
- 🛡️ 可自訂驗證、授權與 Claims
- 🍪 支援 Cookie 與 Header Token
- 📝 易於整合，API 清晰
- 🔐 符合 RFC 6749 規範的刷新 Token（OAuth 2.0 標準）
- 🗄️ 可插拔的刷新 Token 儲存（記憶體、Redis 等）

---

## 安全性注意事項

> **警告：**
> 使用弱密碼（如短或簡單密碼）的 JWT Token 易受暴力破解攻擊。
> **建議：**請使用強且長的密鑰或 `RS256` Token。
> 詳見 [jwt-cracker repository](https://github.com/lmammino/jwt-cracker)。
> **OAuth 2.0 安全性：**
> 此函式庫預設遵循 RFC 6749 OAuth 2.0 標準，使用分離的不透明刷新 Token，
> 這些 Token 在伺服器端儲存並在每次使用時輪替。這比同時使用 JWT Token
> 作為存取與刷新用途提供更好的安全性。

---

## 安裝

### 使用 Go Modules（推薦）

```sh
export GO111MODULE=on
go get github.com/appleboy/gin-jwt/v2
```

```go
import "github.com/appleboy/gin-jwt/v2"
```

---

## 快速開始範例

請參考 [`_example/basic/server.go`](./_example/basic/server.go) 範例檔案，並可使用 `ExtractClaims` 取得 JWT 內的使用者資料。

```go
// ...（完整範例請見 _example/basic/server.go）
```

---

## Demo

啟動範例伺服器：

```sh
go run _example/basic/server.go
```

建議安裝 [httpie](https://github.com/jkbrzt/httpie) 來測試 API。

### 登入

```sh
http -v --json POST localhost:8000/login username=admin password=admin
```

![登入截圖](screenshot/login.png)

### 刷新 Token

使用符合 RFC 6749 規範的刷新 Token（預設行為）：

```sh
# 首先登入取得刷新 Token
http -v --json POST localhost:8000/login username=admin password=admin

# 使用刷新 Token 取得新的存取 Token
http -v --json POST localhost:8000/auth/refresh_token refresh_token=your_refresh_token_here
```

![刷新截圖](screenshot/refresh_token.png)

### Hello World

以 `admin`/`admin` 登入後呼叫：

```sh
http -f GET localhost:8000/auth/hello "Authorization:Bearer xxxxxxxxx"  "Content-Type: application/json"
```

**回應：**

```json
{
  "text": "Hello World.",
  "userID": "admin"
}
```

### 授權範例

以 `test`/`test` 登入後呼叫：

```sh
http -f GET localhost:8000/auth/hello "Authorization:Bearer xxxxxxxxx"  "Content-Type: application/json"
```

**回應：**

```json
{
  "code": 403,
  "message": "You don't have permission to access."
}
```

---

## Cookie Token

若要將 JWT 設定於 Cookie，請使用以下選項（參考 [MDN 文件](https://developer.mozilla.org/zh-TW/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies)）：

```go
SendCookie:       true,
SecureCookie:     false, // 非 HTTPS 開發環境
CookieHTTPOnly:   true,  // JS 無法修改
CookieDomain:     "localhost:8080",
CookieName:       "token", // 預設 jwt
TokenLookup:      "cookie:token",
CookieSameSite:   http.SameSiteDefaultMode, // SameSiteDefaultMode, SameSiteLaxMode, SameSiteStrictMode, SameSiteNoneMode
```

---

### 登入流程（LoginHandler）

- **內建：** `LoginHandler`  
  在登入端點呼叫此函式以觸發登入流程。

- **必須：** `Authenticator`  
  驗證 Gin context 內的使用者憑證。驗證成功後回傳要嵌入 JWT Token 的使用者資料（如帳號、角色等）。失敗則呼叫 `Unauthorized`。

- **可選：** `PayloadFunc`  
  將驗證通過的使用者資料轉為 `MapClaims`（map[string]interface{}），必須包含 `IdentityKey`（預設為 `"identity"`）。

- **可選：** `LoginResponse`  
  處理登入後邏輯，例如回傳 Token JSON。

---

### 需要 JWT Token 的端點（MiddlewareFunc）

- **內建：** `MiddlewareFunc`  
  用於需要 JWT 驗證的端點。會：

  - 從 header/cookie/query 解析 Token
  - 驗證 Token
  - 呼叫 `IdentityHandler` 與 `Authorizator`
  - 驗證失敗則呼叫 `Unauthorized`

- **可選：** `IdentityHandler`  
  從 JWT Claims 取得使用者身份。

- **可選：** `Authorizator`  
  檢查使用者是否有權限存取該端點。

---

### 登出流程（LogoutHandler）

- **內建：** `LogoutHandler`  
  用於登出端點。會清除 Cookie（若 `SendCookie` 設定為 true）並呼叫 `LogoutResponse`。

- **可選：** `LogoutResponse`  
  回傳登出結果的 HTTP 狀態碼。

---

### 刷新流程（RefreshHandler）

- **內建：** `RefreshHandler`  
  用於刷新 Token 端點。若 Token 在 `MaxRefreshTime` 內，會發新 Token 並呼叫 `RefreshResponse`。

- **可選：** `RefreshResponse`  
  回傳新 Token 的 JSON。

---

### 登入失敗、Token 錯誤或權限不足

- **可選：** `Unauthorized`  
  處理登入、授權或 Token 錯誤時的回應。回傳 HTTP 錯誤碼與訊息的 JSON。

---

## 截圖

| 登入                              | 刷新 Token                                |
| --------------------------------- | ----------------------------------------- |
| ![登入截圖](screenshot/login.png) | ![刷新截圖](screenshot/refresh_token.png) |

---

## 授權

詳見 [`LICENSE`](LICENSE)。
