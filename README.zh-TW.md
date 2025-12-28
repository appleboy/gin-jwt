# Gin JWT 中介軟體

[English](README.md) | [繁體中文](README.zh-TW.md) | [简体中文](README.zh-CN.md)

[![Run Tests](https://github.com/appleboy/gin-jwt/actions/workflows/go.yml/badge.svg)](https://github.com/appleboy/gin-jwt/actions/workflows/go.yml)
[![Trivy Security Scan](https://github.com/appleboy/gin-jwt/actions/workflows/trivy-scan.yml/badge.svg)](https://github.com/appleboy/gin-jwt/actions/workflows/trivy-scan.yml)
[![GitHub tag](https://img.shields.io/github/tag/appleboy/gin-jwt.svg)](https://github.com/appleboy/gin-jwt/releases)
[![GoDoc](https://godoc.org/github.com/appleboy/gin-jwt?status.svg)](https://godoc.org/github.com/appleboy/gin-jwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/appleboy/gin-jwt)](https://goreportcard.com/report/github.com/appleboy/gin-jwt)
[![codecov](https://codecov.io/gh/appleboy/gin-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/appleboy/gin-jwt)
[![Sourcegraph](https://sourcegraph.com/github.com/appleboy/gin-jwt/-/badge.svg)](https://sourcegraph.com/github.com/appleboy/gin-jwt?badge)

一個強大且靈活的 [Gin](https://github.com/gin-gonic/gin) Web 框架的 JWT 驗證中介軟體，基於 [golang-jwt/jwt](https://github.com/golang-jwt/jwt) 實作。
輕鬆為你的 Gin 應用程式加入登入、Token 更新與授權功能。

---

## 目錄

- [Gin JWT 中介軟體](#gin-jwt-中介軟體)
  - [目錄](#目錄)
  - [功能特色](#功能特色)
  - [安全性注意事項](#安全性注意事項)
    - [🔒 關鍵安全要求](#-關鍵安全要求)
    - [🛡️ 生產環境安全檢查清單](#️-生產環境安全檢查清單)
    - [🔄 OAuth 2.0 安全標準](#-oauth-20-安全標準)
    - [💡 安全配置範例](#-安全配置範例)
  - [安裝](#安裝)
  - [快速開始範例](#快速開始範例)
  - [使用範例](#使用範例)
    - [🔑 基礎認證](#-基礎認證)
    - [🌐 OAuth SSO 整合](#-oauth-sso-整合)
    - [🔐 Token 產生器](#-token-產生器)
    - [🗄️ Redis 儲存](#️-redis-儲存)
    - [🛡️ 授權控制](#️-授權控制)
  - [配置](#配置)
  - [支援多個 JWT 提供者](#支援多個-jwt-提供者)
    - [使用場景](#使用場景)
    - [解決方案：動態金鑰函數](#解決方案動態金鑰函數)
      - [為什麼這個方法有效](#為什麼這個方法有效)
    - [實作策略](#實作策略)
      - [步驟 1：建立統一的中介軟體](#步驟-1建立統一的中介軟體)
      - [步驟 2：輔助函數](#步驟-2輔助函數)
      - [步驟 3：路由設定](#步驟-3路由設定)
    - [完整的 Azure AD 整合範例](#完整的-azure-ad-整合範例)
    - [替代方法：自訂包裝中介軟體](#替代方法自訂包裝中介軟體)
    - [關鍵考量事項](#關鍵考量事項)
    - [測試多提供者設定](#測試多提供者設定)
    - [常見問題與解決方案](#常見問題與解決方案)
    - [其他資源](#其他資源)
  - [Token 產生器（直接建立 Token）](#token-產生器直接建立-token)
    - [基本用法](#基本用法)
    - [Token 結構](#token-結構)
    - [刷新 Token 管理](#刷新-token-管理)
  - [Redis 儲存配置](#redis-儲存配置)
    - [Redis 功能特色](#redis-功能特色)
    - [Redis 使用方法](#redis-使用方法)
      - [使用函數選項模式（推薦）](#使用函數選項模式推薦)
      - [可用選項](#可用選項)
    - [配置選項](#配置選項)
      - [RedisConfig](#redisconfig)
    - [回退行為](#回退行為)
    - [Redis 範例](#redis-範例)
  - [Demo](#demo)
    - [登入](#登入)
    - [刷新 Token](#刷新-token)
    - [Hello World](#hello-world)
    - [授權範例](#授權範例)
  - [理解 Authorizer](#理解-authorizer)
    - [Authorizer 工作原理](#authorizer-工作原理)
    - [Authorizer 函式簽名](#authorizer-函式簽名)
    - [基本用法範例](#基本用法範例)
      - [範例 1：基於角色的授權](#範例-1基於角色的授權)
      - [範例 2：基於路徑的授權](#範例-2基於路徑的授權)
      - [範例 3：基於方法和路徑的授權](#範例-3基於方法和路徑的授權)
    - [為不同路由設定不同授權](#為不同路由設定不同授權)
      - [方法 1：多個中介軟體實例](#方法-1多個中介軟體實例)
      - [方法 2：帶路徑邏輯的單一 Authorizer](#方法-2帶路徑邏輯的單一-authorizer)
    - [進階授權模式](#進階授權模式)
      - [使用 Claims 進行細緻度控制](#使用-claims-進行細緻度控制)
    - [常見模式和最佳實踐](#常見模式和最佳實踐)
    - [授權完整範例](#授權完整範例)
    - [登出](#登出)
  - [Cookie Token](#cookie-token)
    - [刷新 Token Cookie 支援](#刷新-token-cookie-支援)
    - [登入流程（LoginHandler）](#登入流程loginhandler)
    - [需要 JWT Token 的端點（MiddlewareFunc）](#需要-jwt-token-的端點middlewarefunc)
    - [登出流程（LogoutHandler）](#登出流程logouthandler)
    - [刷新流程（RefreshHandler）](#刷新流程refreshhandler)
    - [登入失敗、Token 錯誤或權限不足](#登入失敗token-錯誤或權限不足)

---

## 功能特色

- 🔒 為 Gin 提供簡單的 JWT 驗證
- 🔁 內建登入、刷新、登出處理器
- 🛡️ 可自訂驗證、授權與 Claims
- 🍪 支援 Cookie 與 Header Token
- 📝 易於整合，API 清晰
- 🔐 符合 RFC 6749 規範的刷新 Token（OAuth 2.0 標準）
- 🗄️ 可插拔的刷新 Token 儲存（記憶體、Redis 用戶端快取）
- 🏭 直接產生 Token，無需 HTTP 中介軟體
- 📦 結構化 Token 類型與中繼資料

---

## 安全性注意事項

### 🔒 關鍵安全要求

> **⚠️ JWT 密鑰安全**
>
> - **最低要求：** 使用至少 **256 位元（32 位元組）** 長度的密鑰
> - **禁止使用：** 簡單密碼、字典詞彙或可預測的模式
> - **建議：** 產生密碼學安全的隨機密鑰或使用 `RS256` 演算法
> - **儲存：** 將密鑰儲存在環境變數中，絕不硬編碼在原始碼中
> - **漏洞：** 弱密鑰易受暴力破解攻擊（[jwt-cracker](https://github.com/lmammino/jwt-cracker)）

### 🛡️ 生產環境安全檢查清單

- ✅ **僅限 HTTPS：** 生產環境中務必使用 HTTPS
- ✅ **強密鑰：** 最少 256 位元隨機產生的密鑰
- ✅ **Token 過期：** 設定適當的過期時間（建議：存取 Token 15-60 分鐘）
- ✅ **安全 Cookie：** 啟用 `SecureCookie`、`CookieHTTPOnly` 和適當的 `SameSite` 設定
- ✅ **環境變數：** 將敏感配置儲存在環境變數中
- ✅ **輸入驗證：** 徹底驗證所有認證輸入

### 🔄 OAuth 2.0 安全標準

此函式庫遵循 **RFC 6749 OAuth 2.0** 安全標準：

- **分離 Token：** 使用不同的不透明刷新 Token（非 JWT）以增強安全性
- **伺服器端儲存：** 刷新 Token 在伺服器端儲存和驗證
- **Token 輪替：** 每次使用時自動輪替刷新 Token
- **增強安全性：** 防止 JWT 刷新 Token 漏洞和重放攻擊

### 💡 安全配置範例

```go
// ❌ 不良：弱密鑰、不安全設定
authMiddleware := &jwt.GinJWTMiddleware{
    Key:         []byte("weak"),           // 太短！
    Timeout:     time.Hour * 24,          // 太長！
    SecureCookie: false,                  // 生產環境不安全！
}

// ✅ 良好：強安全配置
authMiddleware := &jwt.GinJWTMiddleware{
    Key:            []byte(os.Getenv("JWT_SECRET")), // 來自環境變數
    Timeout:        time.Minute * 15,                // 短期存取 Token
    MaxRefresh:     time.Hour * 24 * 7,             // 1 週刷新有效期
    SecureCookie:   true,                           // 僅限 HTTPS
    CookieHTTPOnly: true,                           // 防止 XSS
    CookieSameSite: http.SameSiteStrictMode,        // CSRF 保護
    SendCookie:     true,                           // 啟用安全 Cookie
}
```

**更多安全指導，請參見我們的 [安全最佳實踐指南](_docs/security.md)**

---

## 安裝

需要 Go 1.24+

```bash
go get -u github.com/appleboy/gin-jwt/v3
```

```go
import "github.com/appleboy/gin-jwt/v3"
```

---

## 快速開始範例

請參考 [`_example/basic/server.go`](./_example/basic/server.go) 範例檔案，並可使用 `ExtractClaims` 取得 JWT 內的使用者資料。

```go
package main

import (
  "log"
  "net/http"
  "os"
  "time"

  jwt "github.com/appleboy/gin-jwt/v3"
  "github.com/gin-gonic/gin"
  "github.com/golang-jwt/jwt/v5"
)

type login struct {
  Username string `form:"username" json:"username" binding:"required"`
  Password string `form:"password" json:"password" binding:"required"`
}

var (
  identityKey = "id"
  port        string
)

// User demo
type User struct {
  UserName  string
  FirstName string
  LastName  string
}

func init() {
  port = os.Getenv("PORT")
  if port == "" {
    port = "8000"
  }
}

func main() {
  engine := gin.Default()
  // the jwt middleware
  authMiddleware, err := jwt.New(initParams())
  if err != nil {
    log.Fatal("JWT Error:" + err.Error())
  }

  // initialize middleware
  errInit := authMiddleware.MiddlewareInit()
  if errInit != nil {
    log.Fatal("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
  }

  // register route
  registerRoute(engine, authMiddleware)

  // start http server
  if err = http.ListenAndServe(":"+port, engine); err != nil {
    log.Fatal(err)
  }
}

func registerRoute(r *gin.Engine, handle *jwt.GinJWTMiddleware) {
  // Public routes
  r.POST("/login", handle.LoginHandler)
  r.POST("/refresh", handle.RefreshHandler) // RFC 6749 compliant refresh endpoint

  r.NoRoute(handle.MiddlewareFunc(), handleNoRoute())

  // Protected routes
  auth := r.Group("/auth", handle.MiddlewareFunc())
  auth.GET("/hello", helloHandler)
  auth.POST("/logout", handle.LogoutHandler) // Logout with refresh token revocation
}

func initParams() *jwt.GinJWTMiddleware {
  return &jwt.GinJWTMiddleware{
    Realm:       "test zone",
    Key:         []byte("secret key"),
    Timeout:     time.Hour,
    MaxRefresh:  time.Hour,
    IdentityKey: identityKey,
    PayloadFunc: payloadFunc(),

    IdentityHandler: identityHandler(),
    Authenticator:   authenticator(),
    Authorizer:      authorizer(),
    Unauthorized:    unauthorized(),
    LogoutResponse:  logoutResponse(),
    TokenLookup:     "header: Authorization, query: token, cookie: jwt",
    // TokenLookup: "query:token",
    // TokenLookup: "cookie:token",
    TokenHeadName: "Bearer",
    TimeFunc:      time.Now,
  }
}

func payloadFunc() func(data any) jwt.MapClaims {
  return func(data any) jwt.MapClaims {
    if v, ok := data.(*User); ok {
      return jwt.MapClaims{
        identityKey: v.UserName,
      }
    }
    return jwt.MapClaims{}
  }
}

func identityHandler() func(c *gin.Context) any {
  return func(c *gin.Context) any {
    claims := jwt.ExtractClaims(c)
    return &User{
      UserName: claims[identityKey].(string),
    }
  }
}

func authenticator() func(c *gin.Context) (any, error) {
  return func(c *gin.Context) (any, error) {
    var loginVals login
    if err := c.ShouldBind(&loginVals); err != nil {
      return "", jwt.ErrMissingLoginValues
    }
    userID := loginVals.Username
    password := loginVals.Password

    if (userID == "admin" && password == "admin") || (userID == "test" && password == "test") {
      return &User{
        UserName:  userID,
        LastName:  "Bo-Yi",
        FirstName: "Wu",
      }, nil
    }
    return nil, jwt.ErrFailedAuthentication
  }
}

func authorizer() func(c *gin.Context, data any) bool {
  return func(c *gin.Context, data any) bool {
    if v, ok := data.(*User); ok && v.UserName == "admin" {
      return true
    }
    return false
  }
}

func unauthorized() func(c *gin.Context, code int, message string) {
  return func(c *gin.Context, code int, message string) {
    c.JSON(code, gin.H{
      "code":    code,
      "message": message,
    })
  }
}

func logoutResponse() func(c *gin.Context) {
  return func(c *gin.Context) {
    // This demonstrates that claims are now accessible during logout
    claims := jwt.ExtractClaims(c)
    user, exists := c.Get(identityKey)

    response := gin.H{
      "code":    http.StatusOK,
      "message": "Successfully logged out",
    }

    // Show that we can access user information during logout
    if len(claims) > 0 {
      response["logged_out_user"] = claims[identityKey]
    }
    if exists {
      response["user_info"] = user.(*User).UserName
    }

    c.JSON(http.StatusOK, response)
  }
}

func handleNoRoute() func(c *gin.Context) {
  return func(c *gin.Context) {
    c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
  }
}

func helloHandler(c *gin.Context) {
  claims := jwt.ExtractClaims(c)
  user, _ := c.Get(identityKey)
  c.JSON(200, gin.H{
    "userID":   claims[identityKey],
    "userName": user.(*User).UserName,
    "text":     "Hello World.",
  })
}
```

---

## 使用範例

本專案提供多個完整的範例實作，展示不同的使用情境：

### 🔑 [基礎認證](_example/basic/)

展示基本的 JWT 認證功能，包含登入、受保護路由和 token 驗證。

### 🌐 [OAuth SSO 整合](_example/oauth_sso/)

**OAuth 2.0 單一登入**範例，支援多個身份提供者（Google、GitHub）：

- OAuth 2.0 授權碼流程
- 使用 state token 的 CSRF 保護
- **雙重認證支援**：httpOnly cookies + Authorization headers
- 為瀏覽器和行動應用程式提供安全的 token 傳遞
- 包含互動式 demo 頁面

### 🔐 [Token 產生器](_example/token_generator/)

直接產生 JWT token，無需 HTTP middleware，適用於：

- 程式化認證
- 服務間通訊
- 測試需要認證的端點
- 自訂認證流程

### 🗄️ [Redis 儲存](_example/redis_simple/)

展示 Redis 整合用於 refresh token 儲存，包含：

- 用戶端快取以提升效能
- 自動降級至記憶體儲存
- 生產環境就緒的配置範例

### 🛡️ [授權控制](_example/authorization/)

進階授權模式，包含：

- 基於角色的存取控制
- 基於路徑的授權
- 多個 middleware 實例
- 精細的權限控制

---

## 配置

`GinJWTMiddleware` 結構體提供以下配置選項：

| 選項                   | 類型                                             | 必填 | 預設值                   | 描述                                                                    |
| ---------------------- | ------------------------------------------------ | ---- | ------------------------ | ----------------------------------------------------------------------- |
| Realm                  | `string`                                         | 否   | `"gin jwt"`              | 顯示給使用者的 Realm 名稱。                                             |
| SigningAlgorithm       | `string`                                         | 否   | `"HS256"`                | 簽名演算法 (HS256, HS384, HS512, RS256, RS384, RS512)。                 |
| Key                    | `[]byte`                                         | 是   | -                        | 用於簽名的密鑰。                                                        |
| Timeout                | `time.Duration`                                  | 否   | `time.Hour`              | JWT Token 的有效期。                                                    |
| MaxRefresh             | `time.Duration`                                  | 否   | `0`                      | 刷新 Token 的有效期。                                                   |
| Authenticator          | `func(c *gin.Context) (any, error)`              | 是   | -                        | 驗證使用者的回呼函數。回傳使用者資料。                                  |
| Authorizer             | `func(c *gin.Context, data any) bool`            | 否   | `true`                   | 授權已驗證使用者的回呼函數。                                            |
| PayloadFunc            | `func(data any) jwt.MapClaims`                   | 否   | -                        | 向 Token 新增額外 Payload 資料的回呼函數。                              |
| Unauthorized           | `func(c *gin.Context, code int, message string)` | 否   | -                        | 處理未授權請求的回呼函數。                                              |
| LoginResponse          | `func(c *gin.Context, token *core.Token)`        | 否   | -                        | 處理成功登入回應的回呼函數。                                            |
| LogoutResponse         | `func(c *gin.Context)`                           | 否   | -                        | 處理成功登出回應的回呼函數。                                            |
| RefreshResponse        | `func(c *gin.Context, token *core.Token)`        | 否   | -                        | 處理成功刷新回應的回呼函數。                                            |
| IdentityHandler        | `func(*gin.Context) any`                         | 否   | -                        | 從 Claims 檢索身分的回呼函數。                                          |
| IdentityKey            | `string`                                         | 否   | `"identity"`             | 用於在 Claims 中儲存身分的鍵。                                          |
| TokenLookup            | `string`                                         | 否   | `"header:Authorization"` | 提取 Token 的來源（header, query, cookie）。                            |
| TokenHeadName          | `string`                                         | 否   | `"Bearer"`               | Header 名稱前綴。                                                       |
| TimeFunc               | `func() time.Time`                               | 否   | `time.Now`               | 提供當前時間的函數。                                                    |
| PrivKeyFile            | `string`                                         | 否   | -                        | 私鑰檔案路徑（用於 RS 演算法）。                                        |
| PubKeyFile             | `string`                                         | 否   | -                        | 公鑰檔案路徑（用於 RS 演算法）。                                        |
| SendCookie             | `bool`                                           | 否   | `false`                  | 是否將 Token 作為 Cookie 發送。                                         |
| CookieMaxAge           | `time.Duration`                                  | 否   | `Timeout`                | Cookie 的有效期。                                                       |
| SecureCookie           | `bool`                                           | 否   | `false`                  | 是否對存取權杖使用安全 Cookie（僅限 HTTPS）。刷新權杖 Cookie 始終安全。 |
| CookieHTTPOnly         | `bool`                                           | 否   | `false`                  | 是否使用 HTTPOnly Cookie。                                              |
| CookieDomain           | `string`                                         | 否   | -                        | Cookie 的網域。                                                         |
| CookieName             | `string`                                         | 否   | `"jwt"`                  | Cookie 的名稱。                                                         |
| RefreshTokenCookieName | `string`                                         | 否   | `"refresh_token"`        | 刷新 Token Cookie 的名稱。                                              |
| CookieSameSite         | `http.SameSite`                                  | 否   | -                        | Cookie 的 SameSite 屬性。                                               |
| SendAuthorization      | `bool`                                           | 否   | `false`                  | 是否為每個請求回傳授權 Header。                                         |
| DisabledAbort          | `bool`                                           | 否   | `false`                  | 禁用 context 的 abort()。                                               |
| ParseOptions           | `[]jwt.ParserOption`                             | 否   | -                        | 解析 JWT 的選項。                                                       |

---

## 支援多個 JWT 提供者

在某些場景中，你可能需要接受來自多個來源的 JWT Token，例如你自己的驗證系統和外部身份提供者（如 Azure AD、Auth0 或其他 OAuth 2.0 提供者）。本節說明如何使用 `KeyFunc` 回呼函數實作多提供者 Token 驗證。

### 使用場景

- 🔐 **混合驗證**：同時支援內部和外部驗證
- 🌐 **第三方整合**：接受來自 Azure AD、Google、Auth0 等的 Token
- 🔄 **遷移場景**：從一個驗證系統逐步遷移到另一個
- 🏢 **企業 SSO**：在一般驗證之外支援企業單一登入

### 解決方案：動態金鑰函數

建議的方法是使用**單一中介軟體配合動態 `KeyFunc`**，根據 Token 屬性（例如 issuer claim）來決定適當的驗證方法。

#### 為什麼這個方法有效

`KeyFunc` 回呼函數（auth_jwt.go:41）正是為此目的而設計。它允許你：

- 在驗證前檢查 Token
- 動態選擇正確的簽章金鑰/方法
- 避免串聯多個中介軟體時的中止問題

### 實作策略

#### 步驟 1：建立統一的中介軟體

```go
package main

import (
    "errors"
    "fmt"
    "strings"
    "time"

    jwt "github.com/appleboy/gin-jwt/v3"
    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v5"
)

func createMultiProviderAuthMiddleware() (*jwt.GinJWTMiddleware, error) {
    // 你自己的 JWT 密鑰
    ownSecret := []byte("your-secret-key")

    // Azure AD 公鑰（從 JWKS 端點獲取）
    azurePublicKeys := getAzurePublicKeys()

    return jwt.New(&jwt.GinJWTMiddleware{
        Realm:       "multi-provider-api",
        Key:         ownSecret, // 預設金鑰（必要但可能不會使用）
        IdentityKey: "sub",
        Timeout:     time.Hour,

        // 動態金鑰函數 - 多提供者支援的核心
        KeyFunc: func(token *jwt.Token) (interface{}, error) {
            // 提取 claims 以判斷 Token 來源
            claims, ok := token.Claims.(jwt.MapClaims)
            if !ok {
                return nil, errors.New("invalid claims type")
            }

            // 檢查 issuer claim 以識別 Token 來源
            issuer, _ := claims["iss"].(string)

            // 路由 1：Azure AD Token
            if isAzureADIssuer(issuer) {
                // 驗證演算法
                if token.Method.Alg() != "RS256" {
                    return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
                }

                // 從 Token header 取得金鑰 ID
                keyID, ok := token.Header["kid"].(string)
                if !ok {
                    return nil, errors.New("missing key ID in Azure AD token header")
                }

                // 查找公鑰
                if key, found := azurePublicKeys[keyID]; found {
                    return key, nil
                }
                return nil, fmt.Errorf("unknown Azure AD key ID: %s", keyID)
            }

            // 路由 2：你自己的 Token
            // 驗證簽章方法符合你的配置
            if token.Method.Alg() != "HS256" {
                return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
            }

            return ownSecret, nil
        },

        // 處理不同提供者的不同身份格式
        IdentityHandler: func(c *gin.Context) interface{} {
            claims := jwt.ExtractClaims(c)

            // 嘗試標準 "sub" claim（大多數 OAuth 提供者使用）
            if sub, ok := claims["sub"].(string); ok {
                return sub
            }

            // 回退到自訂 "identity" claim
            if identity, ok := claims["identity"].(string); ok {
                return identity
            }

            return nil
        },

        // 選用：提供者特定的授權
        Authorizer: func(c *gin.Context, data interface{}) bool {
            claims := jwt.ExtractClaims(c)
            issuer, _ := claims["iss"].(string)

            // Azure AD 特定授權
            if isAzureADIssuer(issuer) {
                return authorizeAzureADUser(claims, c)
            }

            // 你自己的 Token 授權
            return authorizeOwnUser(claims, c)
        },

        // 選用：針對不同提供者的自訂錯誤訊息
        HTTPStatusMessageFunc: func(c *gin.Context, e error) string {
            if strings.Contains(e.Error(), "Azure AD") {
                return "Azure AD token validation failed: " + e.Error()
            }
            return e.Error()
        },
    })
}
```

#### 步驟 2：輔助函數

```go
// 檢查 issuer 是否來自 Azure AD
func isAzureADIssuer(issuer string) bool {
    // Azure AD issuer 看起來像：
    // https://login.microsoftonline.com/{tenant}/v2.0
    // https://sts.windows.net/{tenant}/
    return strings.Contains(issuer, "login.microsoftonline.com") ||
           strings.Contains(issuer, "sts.windows.net")
}

// 從 JWKS 端點獲取並快取 Azure AD 公鑰
func getAzurePublicKeys() map[string]interface{} {
    // 實作：從 Azure AD JWKS 端點獲取
    // https://login.microsoftonline.com/common/discovery/v2.0/keys
    // 或特定租戶：https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys

    // 使用函式庫如 github.com/lestrrat-go/jwx/v2/jwk 來解析 JWKS
    // 實作快取以避免每個請求都獲取

    keys := make(map[string]interface{})

    // 範例結構（你需要實作實際的獲取）：
    // jwkSet, err := jwk.Fetch(context.Background(),
    //     "https://login.microsoftonline.com/common/discovery/v2.0/keys")
    // if err != nil {
    //     log.Printf("Failed to fetch Azure AD keys: %v", err)
    //     return keys
    // }
    //
    // for it := jwkSet.Iterate(context.Background()); it.Next(context.Background()); {
    //     pair := it.Pair()
    //     key := pair.Value.(jwk.Key)
    //
    //     var rawKey interface{}
    //     if err := key.Raw(&rawKey); err == nil {
    //         keys[key.KeyID()] = rawKey
    //     }
    // }

    return keys
}

// Azure AD 特定授權
func authorizeAzureADUser(claims jwt.MapClaims, c *gin.Context) bool {
    // 檢查 Azure AD 特定 claims

    // 範例：檢查 roles claim
    if roles, ok := claims["roles"].([]interface{}); ok {
        for _, role := range roles {
            if role.(string) == "Admin" || role.(string) == "User" {
                return true
            }
        }
    }

    // 範例：檢查 groups claim
    if groups, ok := claims["groups"].([]interface{}); ok {
        allowedGroups := []string{"group-id-1", "group-id-2"}
        for _, group := range groups {
            for _, allowed := range allowedGroups {
                if group.(string) == allowed {
                    return true
                }
            }
        }
    }

    // 範例：檢查 app roles
    if appRoles, ok := claims["app_role"].(string); ok {
        if appRoles == "User.Read" || appRoles == "Admin.All" {
            return true
        }
    }

    return false
}

// 你自己的 Token 授權
func authorizeOwnUser(claims jwt.MapClaims, c *gin.Context) bool {
    // 你的自訂授權邏輯
    if role, ok := claims["role"].(string); ok {
        return role == "admin" || role == "user"
    }
    return true
}
```

#### 步驟 3：路由設定

```go
func main() {
    r := gin.Default()

    // 初始化多提供者中介軟體
    authMiddleware, err := createMultiProviderAuthMiddleware()
    if err != nil {
        log.Fatal("JWT Error: " + err.Error())
    }

    if err := authMiddleware.MiddlewareInit(); err != nil {
        log.Fatal("Middleware Init Error: " + err.Error())
    }

    // 公開路由
    r.POST("/login", authMiddleware.LoginHandler) // 用於你自己的驗證
    r.POST("/refresh", authMiddleware.RefreshHandler)

    // 受保護路由 - 接受來自任何已配置提供者的 Token
    auth := r.Group("/api")
    auth.Use(authMiddleware.MiddlewareFunc())
    {
        auth.GET("/profile", func(c *gin.Context) {
            claims := jwt.ExtractClaims(c)
            issuer := claims["iss"].(string)

            c.JSON(200, gin.H{
                "message": "Success",
                "user_id": claims["sub"],
                "issuer":  issuer,
                "source":  determineTokenSource(issuer),
            })
        })
    }

    r.Run(":8080")
}

func determineTokenSource(issuer string) string {
    if isAzureADIssuer(issuer) {
        return "Azure AD"
    }
    return "Internal"
}
```

### 完整的 Azure AD 整合範例

對於生產環境就緒的 Azure AD 整合，你需要：

**動態獲取 JWKS 金鑰**：

```go
import (
    "context"
    "crypto/rsa"
    "sync"
    "time"

    "github.com/lestrrat-go/jwx/v2/jwk"
)

type AzureADKeyProvider struct {
    jwksURL    string
    keys       map[string]*rsa.PublicKey
    mutex      sync.RWMutex
    lastUpdate time.Time
}

func NewAzureADKeyProvider(tenantID string) *AzureADKeyProvider {
    provider := &AzureADKeyProvider{
        jwksURL: fmt.Sprintf(
            "https://login.microsoftonline.com/%s/discovery/v2.0/keys",
            tenantID,
        ),
        keys: make(map[string]*rsa.PublicKey),
    }

    // 初始獲取
    provider.RefreshKeys()

    // 每小時刷新金鑰
    go func() {
        ticker := time.NewTicker(1 * time.Hour)
        defer ticker.Stop()
        for range ticker.C {
            provider.RefreshKeys()
        }
    }()

    return provider
}

func (p *AzureADKeyProvider) RefreshKeys() error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    set, err := jwk.Fetch(ctx, p.jwksURL)
    if err != nil {
        return fmt.Errorf("failed to fetch JWKS: %w", err)
    }

    newKeys := make(map[string]*rsa.PublicKey)

    for it := set.Keys(ctx); it.Next(ctx); {
        key := it.Pair().Value.(jwk.Key)

        var rawKey interface{}
        if err := key.Raw(&rawKey); err != nil {
            continue
        }

        if rsaKey, ok := rawKey.(*rsa.PublicKey); ok {
            newKeys[key.KeyID()] = rsaKey
        }
    }

    p.mutex.Lock()
    p.keys = newKeys
    p.lastUpdate = time.Now()
    p.mutex.Unlock()

    return nil
}

func (p *AzureADKeyProvider) GetKey(keyID string) (*rsa.PublicKey, bool) {
    p.mutex.RLock()
    defer p.mutex.RUnlock()

    key, found := p.keys[keyID]
    return key, found
}
```

**驗證 Azure AD 特定 Claims**：

```go
func validateAzureADClaims(claims jwt.MapClaims) error {
    // 驗證 issuer
    iss, ok := claims["iss"].(string)
    if !ok || !isAzureADIssuer(iss) {
        return errors.New("invalid Azure AD issuer")
    }

    // 驗證 audience（你的應用程式 ID）
    aud, ok := claims["aud"].(string)
    if !ok || aud != "your-app-client-id" {
        return errors.New("invalid audience")
    }

    // 驗證租戶（選用，適用於單租戶應用程式）
    tid, ok := claims["tid"].(string)
    if !ok || tid != "your-tenant-id" {
        return errors.New("invalid tenant")
    }

    return nil
}
```

### 替代方法：自訂包裝中介軟體

如果你需要更多控制或想要完全分離提供者：

```go
func MultiAuthMiddleware(
    ownAuth *jwt.GinJWTMiddleware,
    externalAuth *jwt.GinJWTMiddleware,
) gin.HandlerFunc {
    return func(c *gin.Context) {
        // 先嘗試自己的驗證
        ownAuth.DisabledAbort = true
        ownAuth.MiddlewareFunc()(c)

        // 檢查驗證是否成功
        if _, exists := c.Get("JWT_PAYLOAD"); exists {
            c.Next()
            return
        }

        // 清除錯誤並嘗試外部提供者
        c.Errors = c.Errors[:0]

        externalAuth.DisabledAbort = true
        externalAuth.MiddlewareFunc()(c)

        if _, exists := c.Get("JWT_PAYLOAD"); exists {
            c.Next()
            return
        }

        // 兩者都失敗
        c.JSON(401, gin.H{
            "code":    401,
            "message": "Invalid or missing authentication token",
        })
        c.Abort()
    }
}
```

### 關鍵考量事項

1. **Token Issuer 驗證**：始終驗證 `iss` claim 以確保 Token 來自可信來源
2. **Audience 驗證**：驗證 `aud` claim 符合你的應用程式客戶端 ID
3. **演算法驗證**：確保簽章演算法符合預期（你的 Token 用 HS256，Azure AD 用 RS256）
4. **金鑰快取**：快取來自 JWKS 端點的公鑰以降低延遲
5. **金鑰輪換**：實作自動金鑰刷新以處理提供者的金鑰輪換
6. **錯誤處理**：提供清楚的錯誤訊息指出哪個提供者的驗證失敗
7. **安全性**：絕不跳過簽章驗證或停用安全檢查

### 測試多提供者設定

```bash
# 使用你自己的 Token 測試
curl -H "Authorization: Bearer YOUR_INTERNAL_TOKEN" \
     http://localhost:8080/api/profile

# 使用 Azure AD Token 測試
curl -H "Authorization: Bearer AZURE_AD_TOKEN" \
     http://localhost:8080/api/profile
```

### 常見問題與解決方案

**問題**："串聯中介軟體會導致第一個失敗時中止請求"

- **解決方案**：使用 `KeyFunc` 方法配合單一中介軟體實例

**問題**："Azure AD 公鑰會定期變更"

- **解決方案**：實作自動 JWKS 刷新（如 AzureADKeyProvider 範例所示）

**問題**："不同提供者的 Token 格式不同"

- **解決方案**：在 `IdentityHandler` 中標準化 claims 並處理提供者特定的格式

**問題**："不同提供者的授權邏輯不同"

- **解決方案**：在 `Authorizer` 中檢查 issuer 並路由到提供者特定的邏輯

### 其他資源

- [Azure AD Token 驗證](https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens)
- [JWKS (JSON Web Key Sets)](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [lestrrat-go/jwx 函式庫](https://github.com/lestrrat-go/jwx) 用於 JWKS 處理

---

## Token 產生器（直接建立 Token）

`TokenGenerator` 功能讓你可以直接建立 JWT Token 而無需 HTTP 中介軟體，非常適合程式化驗證、測試和自訂流程。

### 基本用法

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    jwt "github.com/appleboy/gin-jwt/v3"
    gojwt "github.com/golang-jwt/jwt/v5"
)

func main() {
    // 初始化中介軟體
    authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
        Realm:      "example zone",
        Key:        []byte("secret key"),
        Timeout:    time.Hour,
        MaxRefresh: time.Hour * 24,
        PayloadFunc: func(data any) gojwt.MapClaims {
            return gojwt.MapClaims{
                "user_id": data,
            }
        },
    })
    if err != nil {
        log.Fatal("JWT Error:" + err.Error())
    }

    // 建立 Token 操作的 context
    ctx := context.Background()

    // 產生完整的 Token 組（存取 + 刷新 Token）
    userData := "user123"
    tokenPair, err := authMiddleware.TokenGenerator(ctx, userData)
    if err != nil {
        log.Fatal("Failed to generate token pair:", err)
    }

    fmt.Printf("Access Token: %s\n", tokenPair.AccessToken)
    fmt.Printf("Refresh Token: %s\n", tokenPair.RefreshToken)
    fmt.Printf("Expires In: %d seconds\n", tokenPair.ExpiresIn())
}
```

### Token 結構

`TokenGenerator` 方法回傳結構化的 `core.Token`：

```go
type Token struct {
    AccessToken  string `json:"access_token"`   // JWT 存取 Token
    TokenType    string `json:"token_type"`     // 總是 "Bearer"
    RefreshToken string `json:"refresh_token"`  // 不透明刷新 Token
    ExpiresAt    int64  `json:"expires_at"`     // Unix 時間戳
    CreatedAt    int64  `json:"created_at"`     // Unix 時間戳
}

// 輔助方法
func (t *Token) ExpiresIn() int64 // 回傳到期前的秒數
```

### 刷新 Token 管理

使用 `TokenGeneratorWithRevocation` 來刷新 Token 並自動撤銷舊 Token：

```go
// 刷新並自動撤銷舊 Token
newTokenPair, err := authMiddleware.TokenGeneratorWithRevocation(ctx, userData, oldRefreshToken)
if err != nil {
    log.Fatal("Failed to refresh token:", err)
}

// 舊刷新 Token 現在已失效
fmt.Printf("New Access Token: %s\n", newTokenPair.AccessToken)
fmt.Printf("New Refresh Token: %s\n", newTokenPair.RefreshToken)
```

**使用情境：**

- 🔧 **程式化驗證**：服務間通訊
- 🧪 **測試**：為測試驗證端點產生 Token
- 📝 **註冊流程**：使用者註冊後立即發放 Token
- ⚙️ **背景作業**：為自動化流程建立 Token
- 🎛️ **自訂驗證流程**：建立自訂驗證邏輯

詳見[完整範例](_example/token_generator/)。

---

## Redis 儲存配置

此函式庫支援 Redis 作為刷新 Token 儲存後端，並內建用戶端快取以提升效能。相比預設的記憶體儲存，Redis 儲存提供更好的可延展性和持久性。

### Redis 功能特色

- 🔄 **用戶端快取**：內建 Redis 用戶端快取以提升效能
- 🚀 **自動回退**：Redis 連線失敗時自動回退到記憶體儲存
- ⚙️ **簡易配置**：簡單的方法配置 Redis 儲存
- 🔧 **方法鏈**：流暢的 API，便於配置
- 📦 **工廠模式**：同時支援 Redis 和記憶體儲存

### Redis 使用方法

#### 使用函數選項模式（推薦）

Redis 配置現在使用函數選項模式，提供更清潔且靈活的配置：

```go
// 方法 1：使用預設配置啟用 Redis
middleware := &jwt.GinJWTMiddleware{
    // ... 其他配置
}.EnableRedisStore()

// 方法 2：使用自訂位址啟用 Redis
middleware := &jwt.GinJWTMiddleware{
    // ... 其他配置
}.EnableRedisStore(
    jwt.WithRedisAddr("redis.example.com:6379"),
)

// 方法 3：使用認證啟用 Redis
middleware := &jwt.GinJWTMiddleware{
    // ... 其他配置
}.EnableRedisStore(
    jwt.WithRedisAddr("redis.example.com:6379"),
    jwt.WithRedisAuth("password", 0),
)

// 方法 4：使用所有選項的完整配置
middleware := &jwt.GinJWTMiddleware{
    // ... 其他配置
}.EnableRedisStore(
    jwt.WithRedisAddr("redis.example.com:6379"),
    jwt.WithRedisAuth("password", 1),
    jwt.WithRedisCache(128*1024*1024, time.Minute),     // 128MB 快取，1分鐘 TTL
    jwt.WithRedisPool(20, time.Hour, 2*time.Hour),      // 連線池配置
    jwt.WithRedisKeyPrefix("myapp:jwt:"),               // 鍵前綴
)

// 方法 5：使用 TLS 啟用 Redis（用於安全連線）
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
}
middleware := &jwt.GinJWTMiddleware{
    // ... 其他配置
}.EnableRedisStore(
    jwt.WithRedisAddr("redis.example.com:6380"),        // TLS 埠
    jwt.WithRedisAuth("password", 0),
    jwt.WithRedisTLS(tlsConfig),                        // 啟用 TLS
)
```

#### 可用選項

- `WithRedisAddr(addr string)` - 設定 Redis 伺服器位址
- `WithRedisAuth(password string, db int)` - 設定認證和資料庫
- `WithRedisTLS(tlsConfig *tls.Config)` - 設定 TLS 配置以進行安全連線
- `WithRedisCache(size int, ttl time.Duration)` - 配置用戶端快取
- `WithRedisPool(poolSize int, maxIdleTime, maxLifetime time.Duration)` - 配置連線池
- `WithRedisKeyPrefix(prefix string)` - 設定 Redis 鍵的前綴

### 配置選項

#### RedisConfig

- **Addr**：Redis 伺服器位址（預設：`"localhost:6379"`）
- **Password**：Redis 密碼（預設：`""`）
- **DB**：Redis 資料庫編號（預設：`0`）
- **TLSConfig**：用於安全連線的 TLS 配置（預設：`nil`）
- **CacheSize**：用戶端快取大小（位元組）（預設：`128MB`）
- **CacheTTL**：用戶端快取 TTL（預設：`1 分鐘`）
- **KeyPrefix**：所有 Redis 鍵的前綴（預設：`"gin-jwt:"`）

### 回退行為

如果在初始化期間 Redis 連線失敗：

- 中介軟體會記錄錯誤訊息
- 自動回退到記憶體儲存
- 應用程式繼續正常運作

這確保了高可用性，防止因 Redis 連線問題導致的應用程式故障。

### Redis 範例

參見[Redis 範例](_example/redis_simple/)了解完整實作。

```go
package main

import (
    "log"
    "net/http"
    "time"

    jwt "github.com/appleboy/gin-jwt/v3"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
        Realm:       "example zone",
        Key:         []byte("secret key"),
        Timeout:     time.Hour,
        MaxRefresh:  time.Hour * 24,
        IdentityKey: "id",

        PayloadFunc: func(data any) jwt.MapClaims {
            if v, ok := data.(map[string]any); ok {
                return jwt.MapClaims{
                    "id": v["username"],
                }
            }
            return jwt.MapClaims{}
        },

        Authenticator: func(c *gin.Context) (any, error) {
            var loginVals struct {
                Username string `json:"username"`
                Password string `json:"password"`
            }

            if err := c.ShouldBind(&loginVals); err != nil {
                return "", jwt.ErrMissingLoginValues
            }

            if loginVals.Username == "admin" && loginVals.Password == "admin" {
                return map[string]any{
                    "username": loginVals.Username,
                }, nil
            }

            return nil, jwt.ErrFailedAuthentication
        },
    }).EnableRedisStore(                                            // 使用選項啟用 Redis
        jwt.WithRedisAddr("localhost:6379"),                       // Redis 伺服器位址
        jwt.WithRedisCache(64*1024*1024, 30*time.Second),         // 64MB 快取，30秒 TTL
    )

    if err != nil {
        log.Fatal("JWT Error:" + err.Error())
    }

    errInit := authMiddleware.MiddlewareInit()
    if errInit != nil {
        log.Fatal("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
    }

    r.POST("/login", authMiddleware.LoginHandler)

    auth := r.Group("/auth")
    auth.Use(authMiddleware.MiddlewareFunc())
    {
        auth.GET("/hello", func(c *gin.Context) {
            c.JSON(200, gin.H{
                "message": "Hello World.",
            })
        })
        auth.GET("/refresh_token", authMiddleware.RefreshHandler)
    }

    if err := http.ListenAndServe(":8000", r); err != nil {
        log.Fatal(err)
    }
}
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

# 方法 1：啟用 Cookie 時（自動 - 推薦用於瀏覽器）
# 刷新 Token Cookie 會自動發送，無需手動包含
http -v POST localhost:8000/refresh --session=./session.json

# 方法 2：在 JSON 本體中發送刷新 Token
http -v --json POST localhost:8000/refresh refresh_token=your_refresh_token_here

# 方法 3：透過表單資料使用回應中的刷新 Token
http -v --form POST localhost:8000/refresh refresh_token=your_refresh_token_here
```

**安全提示**：當 `SendCookie` 啟用時，刷新權杖會自動儲存在 httpOnly Cookie 中。基於瀏覽器的應用程式只需呼叫刷新端點，無需手動包含權杖，Cookie 機制會自動處理。

**重要**：不支援使用查詢參數傳遞刷新權杖，因為它們會在伺服器日誌、代理日誌、瀏覽器歷史記錄和 Referer 標頭中暴露權杖。請使用 Cookie（推薦）、JSON 本體或表單資料。

![刷新截圖](screenshot/refresh.png)

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

## 理解 Authorizer

`Authorizer` 函式是在應用程式中實作基於角色的存取控制的關鍵組件。它決定已驗證使用者是否有權限存取特定的受保護路由。

### Authorizer 工作原理

`Authorizer` 在使用 `MiddlewareFunc()` 的任何路由的 JWT 中介軟體處理過程中**自動呼叫**。執行流程如下：

1. **Token 驗證**：JWT 中介軟體驗證 token
2. **身份提取**：`IdentityHandler` 從 token claims 中提取使用者身份
3. **授權檢查**：`Authorizer` 決定使用者是否可以存取資源
4. **路由存取**：如果授權通過，請求繼續；否則呼叫 `Unauthorized`

### Authorizer 函式簽名

```go
func(c *gin.Context, data any) bool
```

- `c *gin.Context`：包含請求資訊的 Gin 上下文
- `data any`：由 `IdentityHandler` 回傳的使用者身份資料
- 回傳 `bool`：`true` 表示授權存取，`false` 表示拒絕存取

### 基本用法範例

#### 範例 1：基於角色的授權

```go
func authorizeHandler() func(c *gin.Context, data any) bool {
    return func(c *gin.Context, data any) bool {
        if v, ok := data.(*User); ok && v.UserName == "admin" {
            return true  // 只有 admin 使用者可以存取
        }
        return false
    }
}
```

#### 範例 2：基於路徑的授權

```go
func authorizeHandler() func(c *gin.Context, data any) bool {
    return func(c *gin.Context, data any) bool {
        user, ok := data.(*User)
        if !ok {
            return false
        }

        path := c.Request.URL.Path

        // Admin 可以存取所有路由
        if user.Role == "admin" {
            return true
        }

        // 普通使用者只能存取 /auth/profile 和 /auth/hello
        allowedPaths := []string{"/auth/profile", "/auth/hello"}
        for _, allowedPath := range allowedPaths {
            if path == allowedPath {
                return true
            }
        }

        return false
    }
}
```

#### 範例 3：基於方法和路徑的授權

```go
func authorizeHandler() func(c *gin.Context, data any) bool {
    return func(c *gin.Context, data any) bool {
        user, ok := data.(*User)
        if !ok {
            return false
        }

        path := c.Request.URL.Path
        method := c.Request.Method

        // 管理員擁有完全存取權限
        if user.Role == "admin" {
            return true
        }

        // 使用者只能 GET 自己的資料
        if path == "/auth/profile" && method == "GET" {
            return true
        }

        // 使用者不能修改或刪除資源
        if method == "POST" || method == "PUT" || method == "DELETE" {
            return false
        }

        return true // 允許其他 GET 請求
    }
}
```

### 為不同路由設定不同授權

要為不同的路由群組實作不同的授權規則，可以建立多個中介軟體實例或在單個 Authorizer 中使用路徑檢查：

#### 方法 1：多個中介軟體實例

```go
// 僅限管理員的中介軟體
adminMiddleware, _ := jwt.New(&jwt.GinJWTMiddleware{
    // ... 其他設定
    Authorizer: func(c *gin.Context, data any) bool {
        if user, ok := data.(*User); ok {
            return user.Role == "admin"
        }
        return false
    },
})

// 普通使用者中介軟體
userMiddleware, _ := jwt.New(&jwt.GinJWTMiddleware{
    // ... 其他設定
    Authorizer: func(c *gin.Context, data any) bool {
        if user, ok := data.(*User); ok {
            return user.Role == "user" || user.Role == "admin"
        }
        return false
    },
})

// 路由設定
adminRoutes := r.Group("/admin", adminMiddleware.MiddlewareFunc())
userRoutes := r.Group("/user", userMiddleware.MiddlewareFunc())
```

#### 方法 2：帶路徑邏輯的單一 Authorizer

```go
func authorizeHandler() func(c *gin.Context, data any) bool {
    return func(c *gin.Context, data any) bool {
        user, ok := data.(*User)
        if !ok {
            return false
        }

        path := c.Request.URL.Path

        // 管理員路由 - 只允許管理員
        if strings.HasPrefix(path, "/admin/") {
            return user.Role == "admin"
        }

        // 使用者路由 - 允許使用者和管理員
        if strings.HasPrefix(path, "/user/") {
            return user.Role == "user" || user.Role == "admin"
        }

        // 公開認證路由 - 所有已認證使用者
        return true
    }
}
```

### 進階授權模式

#### 使用 Claims 進行細緻度控制

```go
func authorizeHandler() func(c *gin.Context, data any) bool {
    return func(c *gin.Context, data any) bool {
        // 提取額外的 claims
        claims := jwt.ExtractClaims(c)

        // 從 claims 取得使用者權限
        permissions, ok := claims["permissions"].([]interface{})
        if !ok {
            return false
        }

        // 檢查使用者是否擁有此路由所需的權限
        requiredPermission := getRequiredPermission(c.Request.URL.Path)

        for _, perm := range permissions {
            if perm.(string) == requiredPermission {
                return true
            }
        }

        return false
    }
}

func getRequiredPermission(path string) string {
    permissionMap := map[string]string{
        "/auth/users":    "read_users",
        "/auth/reports":  "read_reports",
        "/auth/settings": "admin",
    }
    return permissionMap[path]
}
```

### 常見模式和最佳實踐

1. **始終驗證資料類型**：檢查使用者資料是否可以轉換為您期望的類型
2. **使用 claims 取得額外上下文**：使用 `jwt.ExtractClaims(c)` 存取 JWT claims
3. **考慮請求上下文**：使用 `c.Request.URL.Path`、`c.Request.Method` 等
4. **安全優先**：預設回傳 `false`，明確允許存取
5. **記錄授權失敗**：新增日誌以除錯授權問題

### 授權完整範例

查看[授權範例](_example/authorization/)了解展示不同授權情境的完整實作。

### 登出

先登入取得 JWT Token，然後呼叫登出端點：

```sh
# 先登入取得 JWT Token
http -v --json POST localhost:8000/login username=admin password=admin

# 使用取得的 JWT Token 來登出（將 xxxxxxxxx 替換為實際的 Token）
http -f POST localhost:8000/auth/logout "Authorization:Bearer xxxxxxxxx" "Content-Type: application/json"
```

**回應：**

```json
{
  "code": 200,
  "logged_out_user": "admin",
  "message": "Successfully logged out",
  "user_info": "admin"
}
```

登出回應展示了 JWT 聲明現在可以透過 `jwt.ExtractClaims(c)` 在登出期間存取，讓開發者能夠取得使用者資訊用於日誌記錄、稽核或清理作業。

---

## Cookie Token

若要將 JWT 設定於 Cookie，請使用以下選項（參考 [MDN 文件](https://developer.mozilla.org/zh-TW/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies)）：

```go
SendCookie:            true,
SecureCookie:          false, // 非 HTTPS 開發環境（僅適用於存取權杖 Cookie）
CookieHTTPOnly:        true,  // JS 無法修改
CookieDomain:          "localhost:8080",
CookieName:            "token", // 預設 jwt
RefreshTokenCookieName: "refresh_token", // 預設 refresh_token
TokenLookup:           "cookie:token",
CookieSameSite:        http.SameSiteDefaultMode, // SameSiteDefaultMode, SameSiteLaxMode, SameSiteStrictMode, SameSiteNoneMode
```

### 刷新 Token Cookie 支援

當 `SendCookie` 啟用時，中介軟體會自動將存取權杖和刷新權杖儲存為 httpOnly Cookie：

- **存取權杖 Cookie**：使用 `CookieName` 指定的名稱儲存（預設：`"jwt"`）
- **刷新權杖 Cookie**：使用 `RefreshTokenCookieName` 指定的名稱儲存（預設：`"refresh_token"`）

刷新權杖 Cookie：

- 使用 `RefreshTokenTimeout` 期限（預設：30 天）
- 永遠設定 `httpOnly: true` 以確保安全
- 永遠設定 `secure: true`（僅限 HTTPS），不受 `SecureCookie` 設定影響
- 會自動隨刷新請求一起發送
- 登出時會被清除

**自動提取權杖**：`RefreshHandler` 會依序自動從 Cookie、表單資料、查詢參數或 JSON 本體中提取刷新權杖。這意味著使用基於 Cookie 的認證時，您無需手動包含刷新權杖，一切都是自動處理的。

---

### 登入流程（LoginHandler）

- **內建：** `LoginHandler`  
  在登入端點呼叫此函式以觸發登入流程。

- **必須：** `Authenticator`  
  驗證 Gin context 內的使用者憑證。驗證成功後回傳要嵌入 JWT Token 的使用者資料（如帳號、角色等）。失敗則呼叫 `Unauthorized`。

- **可選：** `PayloadFunc`
  將驗證通過的使用者資料轉為 `MapClaims`（map[string]any），必須包含 `IdentityKey`（預設為 `"identity"`）。

  **標準 JWT Claims（RFC 7519）：** 您可以在 `PayloadFunc` 中設定標準 JWT claims 以提高互通性：

  - `sub`（Subject）- 使用者識別碼（例如使用者 ID）
  - `iss`（Issuer）- Token 簽發者（例如您的應用程式名稱）
  - `aud`（Audience）- 預期的接收方（例如您的 API）
  - `nbf`（Not Before）- Token 在此時間之前無效
  - `iat`（Issued At）- Token 簽發時間
  - `jti`（JWT ID）- Token 的唯一識別碼

  **注意：** `exp`（過期時間）和 `orig_iat` claims 由框架管理，無法覆寫。

  ```go
  PayloadFunc: func(data any) jwt.MapClaims {
      if user, ok := data.(*User); ok {
          return jwt.MapClaims{
              "sub":      user.ID,              // 標準：Subject（使用者 ID）
              "iss":      "my-app",             // 標準：Issuer
              "aud":      "my-api",             // 標準：Audience
              "identity": user.UserName,        // 自訂 claim
              "role":     user.Role,            // 自訂 claim
          }
      }
      return jwt.MapClaims{}
  }
  ```

- **可選：** `LoginResponse`
  在成功透過 `Authenticator` 驗證、使用從 `PayloadFunc` 回傳的識別資訊建立 JWT Token，並在 `SendCookie` 啟用時設定 Cookie 之後，會呼叫此函式。

  當 `SendCookie` 啟用時，中介軟體會在呼叫此函式之前自動設定兩個 httpOnly Cookie：

  - **存取權杖 Cookie**：根據 `CookieName` 命名（預設：`"jwt"`）
  - **刷新權杖 Cookie**：根據 `RefreshTokenCookieName` 命名（預設：`"refresh_token"`）

  此函式接收完整的 token 資訊（包括存取 token、刷新 token、到期時間等）作為結構化的 `core.Token` 物件，用於處理登入後邏輯並回傳 token 回應給用戶。

  函式簽名：`func(c *gin.Context, token *core.Token)`

---

### 需要 JWT Token 的端點（MiddlewareFunc）

- **內建：** `MiddlewareFunc`  
  用於需要 JWT 驗證的端點。會：

  - 從 header/cookie/query 解析 Token
  - 驗證 Token
  - 呼叫 `IdentityHandler` 與 `Authorizer`
  - 驗證失敗則呼叫 `Unauthorized`

- **可選：** `IdentityHandler`  
  從 JWT Claims 取得使用者身份。

- **可選：** `Authorizer`  
  檢查使用者是否有權限存取該端點。

---

### 登出流程（LogoutHandler）

- **內建：** `LogoutHandler`
  用於登出端點的內建函式。處理器會執行以下動作：

  1. 提取 JWT 聲明以便在 `LogoutResponse` 中使用（用於日誌記錄/稽核）
  2. 如果提供了刷新權杖，嘗試從伺服器端儲存區撤銷它
  3. 如果 `SendCookie` 啟用，清除認證 Cookie：
     - **存取權杖 Cookie**：根據 `CookieName` 命名
     - **刷新權杖 Cookie**：根據 `RefreshTokenCookieName` 命名
  4. 呼叫 `LogoutResponse` 回傳回應

  登出處理器會嘗試從多個來源（Cookie、表單、查詢參數、JSON 本體）提取刷新權杖，以確保能正確撤銷。

- **可選：** `LogoutResponse`
  在登出處理完成後呼叫此函式。應回傳適當的 HTTP 回應以表示登出成功或失敗。由於登出不會產生新的 token，此函式只接收 gin context。您可以透過 `jwt.ExtractClaims(c)` 和 `c.Get(identityKey)` 存取 JWT 聲明和使用者身份，用於日誌記錄或稽核。

  函式簽名：`func(c *gin.Context)`

---

### 刷新流程（RefreshHandler）

- **內建：** `RefreshHandler`
  用於刷新 Token 端點的內建函式。處理器預期從多個來源接收符合 RFC 6749 規範的 `refresh_token` 參數，並根據伺服器端 token 儲存區進行驗證。處理器會按照優先順序自動從以下來源提取刷新權杖：

  1. **Cookie**（最常用於瀏覽器應用程式）：`RefreshTokenCookieName` Cookie（預設：`"refresh_token"`）
  2. **POST 表單**：`refresh_token` 表單欄位
  3. **查詢參數**：`refresh_token` 查詢字串參數
  4. **JSON 本體**：請求本體中的 `refresh_token` 欄位

  如果刷新權杖有效且未過期，處理器會：

  - 建立新的存取權杖和刷新權杖
  - 撤銷舊的刷新權杖（權杖輪換）
  - 如果 `SendCookie` 啟用，設定兩個權杖作為 Cookie
  - 將新權杖傳遞給 `RefreshResponse`

  這遵循 OAuth 2.0 安全最佳實踐，通過輪換刷新權杖並支援多種傳遞方法。

  **基於 Cookie 的認證**：使用 Cookie 時（推薦用於瀏覽器應用程式），刷新權杖會自動隨請求一起發送，因此您無需手動包含它。只需呼叫刷新端點，中介軟體會處理一切。

- **可選：** `RefreshResponse`
  在成功刷新 token 後呼叫此函式。接收完整的新 token 資訊作為結構化的 `core.Token` 物件，應回傳包含新 `access_token`、`token_type`、`expires_in` 和 `refresh_token` 欄位的 JSON 回應，遵循 RFC 6749 token 回應格式。請注意，使用 Cookie 時，權杖在呼叫此函式之前已經設定為 httpOnly Cookie。

  函式簽名：`func(c *gin.Context, token *core.Token)`

---

### 登入失敗、Token 錯誤或權限不足

- **可選：** `Unauthorized`
  處理登入、授權或 Token 錯誤時的回應。回傳 HTTP 錯誤碼與訊息的 JSON。

**注意：** 當回傳 401 Unauthorized 回應時，中介軟體會自動新增 `WWW-Authenticate` 標頭，使用 `Bearer` 認證方案，符合 [RFC 6750](https://tools.ietf.org/html/rfc6750)（OAuth 2.0 Bearer Token 使用規範）、[RFC 7235](https://tools.ietf.org/html/rfc7235)（HTTP 認證框架）和 [MDN 文件](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401)的要求：

```txt
WWW-Authenticate: Bearer realm="<your-realm>"
```

該標頭告知 HTTP 客戶端需要 Bearer Token 認證，確保與標準 HTTP 認證機制的相容性。
