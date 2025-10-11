# Gin JWT 中间件

[English](README.md) | [繁體中文](README.zh-TW.md) | [简体中文](README.zh-CN.md)

[![Run Tests](https://github.com/appleboy/gin-jwt/actions/workflows/go.yml/badge.svg)](https://github.com/appleboy/gin-jwt/actions/workflows/go.yml)
[![GitHub tag](https://img.shields.io/github/tag/appleboy/gin-jwt.svg)](https://github.com/appleboy/gin-jwt/releases)
[![GoDoc](https://godoc.org/github.com/appleboy/gin-jwt?status.svg)](https://godoc.org/github.com/appleboy/gin-jwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/appleboy/gin-jwt)](https://goreportcard.com/report/github.com/appleboy/gin-jwt)
[![codecov](https://codecov.io/gh/appleboy/gin-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/appleboy/gin-jwt)
[![Sourcegraph](https://sourcegraph.com/github.com/appleboy/gin-jwt/-/badge.svg)](https://sourcegraph.com/github.com/appleboy/gin-jwt?badge)

一个强大且灵活的 [Gin](https://github.com/gin-gonic/gin) Web 框架的 JWT 认证中间件，基于 [jwt-go](https://github.com/golang-jwt/jwt) 实现。  
轻松为你的 Gin 应用添加登录、Token 刷新与授权功能。

---

## 目录

- [Gin JWT 中间件](#gin-jwt-中间件)
  - [目录](#目录)
  - [功能特色](#功能特色)
  - [安全性注意事项](#安全性注意事项)
  - [安装](#安装)
    - [使用 Go Modules（推荐）](#使用-go-modules推荐)
  - [快速开始示例](#快速开始示例)
  - [Demo](#demo)
    - [登录](#登录)
    - [刷新 Token](#刷新-token)
    - [Hello World](#hello-world)
    - [授权示例](#授权示例)
  - [Cookie Token](#cookie-token)
    - [登录流程（LoginHandler）](#登录流程loginhandler)
    - [需要 JWT Token 的端点（MiddlewareFunc）](#需要-jwt-token-的端点middlewarefunc)
    - [登出流程（LogoutHandler）](#登出流程logouthandler)
    - [刷新流程（RefreshHandler）](#刷新流程refreshhandler)
    - [登录失败、Token 错误或权限不足](#登录失败token-错误或权限不足)
  - [截图](#截图)
  - [授权](#授权)

---

## 功能特色

- 🔒 为 Gin 提供简单的 JWT 认证
- 🔁 内置登录、刷新、登出处理器
- 🛡️ 可自定义认证、授权与 Claims
- 🍪 支持 Cookie 与 Header Token
- 📝 易于集成，API 清晰
- 🔐 符合 RFC 6749 规范的刷新令牌（OAuth 2.0 标准）
- 🗄️ 可插拔的刷新令牌存储（内存、Redis 等）

---

## 安全性注意事项

> **警告：**
> 使用弱密码（如短或简单密码）的 JWT Token 易受暴力破解攻击。
> **建议：**请使用强且长的密钥或 `RS256` Token。
> 详见 [jwt-cracker repository](https://github.com/lmammino/jwt-cracker)。
> **OAuth 2.0 安全性：**
> 此库默认遵循 RFC 6749 OAuth 2.0 标准，使用分离的不透明刷新令牌，
> 这些令牌在服务器端存储并在每次使用时轮替。这比同时使用 JWT 令牌
> 作为访问和刷新用途提供更好的安全性。

---

## 安装

### 使用 Go Modules（推荐）

```sh
export GO111MODULE=on
go get github.com/appleboy/gin-jwt/v2
```

```go
import "github.com/appleboy/gin-jwt/v2"
```

---

## 快速开始示例

请参考 [`_example/basic/server.go`](./_example/basic/server.go) 示例文件，并可使用 `ExtractClaims` 获取 JWT 内的用户数据。

```go
// ...（完整示例请见 _example/basic/server.go）
```

---

## Demo

启动示例服务器：

```sh
go run _example/basic/server.go
```

建议安装 [httpie](https://github.com/jkbrzt/httpie) 进行 API 测试。

### 登录

```sh
http -v --json POST localhost:8000/login username=admin password=admin
```

![登录截图](screenshot/login.png)

### 刷新 Token

使用符合 RFC 6749 规范的刷新令牌（默认行为）：

```sh
# 首先登录获取刷新令牌
http -v --json POST localhost:8000/login username=admin password=admin

# 使用刷新令牌获取新的访问令牌（公开端点）
http -v --form POST localhost:8000/refresh refresh_token=your_refresh_token_here
```

![刷新截图](screenshot/refresh.png)

### Hello World

以 `admin`/`admin` 登录后调用：

```sh
http -f GET localhost:8000/auth/hello "Authorization:Bearer xxxxxxxxx"  "Content-Type: application/json"
```

**响应：**

```json
{
  "text": "Hello World.",
  "userID": "admin"
}
```

### 授权示例

以 `test`/`test` 登录后调用：

```sh
http -f GET localhost:8000/auth/hello "Authorization:Bearer xxxxxxxxx"  "Content-Type: application/json"
```

**响应：**

```json
{
  "code": 403,
  "message": "You don't have permission to access."
}
```

### 登出

先登录获取 JWT Token，然后调用登出端点：

```sh
# 先登录获取 JWT Token
http -v --json POST localhost:8000/login username=admin password=admin

# 使用获取的 JWT Token 来登出（将 xxxxxxxxx 替换为实际的 Token）
http -f POST localhost:8000/auth/logout "Authorization:Bearer xxxxxxxxx" "Content-Type: application/json"
```

**响应：**

```json
{
  "code": 200,
  "logged_out_user": "admin",
  "message": "Successfully logged out",
  "user_info": "admin"
}
```

登出响应展示了 JWT 声明现在可以通过 `jwt.ExtractClaims(c)` 在登出期间访问，让开发者能够获取用户信息用于日志记录、审计或清理操作。

---

## Cookie Token

如需将 JWT 设置于 Cookie，请使用以下选项（参考 [MDN 文档](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies)）：

```go
SendCookie:       true,
SecureCookie:     false, // 非 HTTPS 开发环境
CookieHTTPOnly:   true,  // JS 无法修改
CookieDomain:     "localhost:8080",
CookieName:       "token", // 默认 jwt
TokenLookup:      "cookie:token",
CookieSameSite:   http.SameSiteDefaultMode, // SameSiteDefaultMode, SameSiteLaxMode, SameSiteStrictMode, SameSiteNoneMode
```

---

### 登录流程（LoginHandler）

- **内置：** `LoginHandler`  
  在登录端点调用此函数以触发登录流程。

- **必须：** `Authenticator`  
  验证 Gin context 内的用户凭证。验证成功后返回要嵌入 JWT Token 的用户数据（如账号、角色等）。失败则调用 `Unauthorized`。

- **可选：** `PayloadFunc`  
  将认证通过的用户数据转为 `MapClaims`（map[string]interface{}），必须包含 `IdentityKey`（默认 `"identity"`）。

- **可选：** `LoginResponse`  
  处理登录后逻辑，例如返回 Token JSON。

---

### 需要 JWT Token 的端点（MiddlewareFunc）

- **内置：** `MiddlewareFunc`  
  用于需要 JWT 认证的端点。会：

  - 从 header/cookie/query 解析 Token
  - 验证 Token
  - 调用 `IdentityHandler` 与 `Authorizator`
  - 验证失败则调用 `Unauthorized`

- **可选：** `IdentityHandler`  
  从 JWT Claims 获取用户身份。

- **可选：** `Authorizator`  
  检查用户是否有权限访问该端点。

---

### 登出流程（LogoutHandler）

- **内置：** `LogoutHandler`  
  用于登出端点。会清除 Cookie（若 `SendCookie` 设置为 true）并调用 `LogoutResponse`。

- **可选：** `LogoutResponse`  
  返回登出结果的 HTTP 状态码。

---

### 刷新流程（RefreshHandler）

- **内置：** `RefreshHandler`  
  用于刷新 Token 端点。若 Token 在 `MaxRefreshTime` 内，会发新 Token 并调用 `RefreshResponse`。

- **可选：** `RefreshResponse`  
  返回新 Token 的 JSON。

---

### 登录失败、Token 错误或权限不足

- **可选：** `Unauthorized`  
  处理登录、授权或 Token 错误时的响应。返回 HTTP 错误码与消息的 JSON。

---

## 截图

| 登录                              | 刷新 Token                                |
| --------------------------------- | ----------------------------------------- |
| ![登录截图](screenshot/login.png) | ![刷新截图](screenshot/refresh_token.png) |

---

## 授权

详见 [`LICENSE`](LICENSE)。
