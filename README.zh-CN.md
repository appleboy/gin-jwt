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
    - [🔒 关键安全要求](#-关键安全要求)
    - [🛡️ 生产环境安全检查清单](#️-生产环境安全检查清单)
    - [🔄 OAuth 2.0 安全标准](#-oauth-20-安全标准)
    - [💡 安全配置示例](#-安全配置示例)
  - [安装](#安装)
  - [快速开始示例](#快速开始示例)
  - [Token 生成器（直接创建 Token）](#token-生成器直接创建-token)
    - [基本用法](#基本用法)
    - [Token 结构](#token-结构)
    - [刷新 Token 管理](#刷新-token-管理)
  - [Redis 存储配置](#redis-存储配置)
    - [Redis 功能特色](#redis-功能特色)
    - [Redis 使用方法](#redis-使用方法)
      - [使用函数选项模式（推荐）](#使用函数选项模式推荐)
      - [可用选项](#可用选项)
    - [配置选项](#配置选项)
      - [RedisConfig](#redisconfig)
    - [回退行为](#回退行为)
    - [Redis 示例](#redis-示例)
  - [Demo](#demo)
    - [登录](#登录)
    - [刷新 Token](#刷新-token)
    - [Hello World](#hello-world)
    - [授权示例](#授权示例)
  - [理解 Authorizer](#理解-authorizer)
    - [Authorizer 工作原理](#authorizer-工作原理)
    - [Authorizer 函数签名](#authorizer-函数签名)
    - [基本用法示例](#基本用法示例)
      - [示例 1：基于角色的授权](#示例-1基于角色的授权)
      - [示例 2：基于路径的授权](#示例-2基于路径的授权)
      - [示例 3：基于方法和路径的授权](#示例-3基于方法和路径的授权)
    - [为不同路由设置不同授权](#为不同路由设置不同授权)
      - [方法 1：多个中间件实例](#方法-1多个中间件实例)
      - [方法 2：带路径逻辑的单一 Authorizer](#方法-2带路径逻辑的单一-authorizer)
    - [高级授权模式](#高级授权模式)
      - [使用 Claims 进行细粒度控制](#使用-claims-进行细粒度控制)
    - [常见模式和最佳实践](#常见模式和最佳实践)
    - [完整示例](#完整示例)
    - [登出](#登出)
  - [Cookie Token](#cookie-token)
    - [登录流程（LoginHandler）](#登录流程loginhandler)
    - [需要 JWT Token 的端点（MiddlewareFunc）](#需要-jwt-token-的端点middlewarefunc)
    - [登出流程（LogoutHandler）](#登出流程logouthandler)
    - [刷新流程（RefreshHandler）](#刷新流程refreshhandler)
    - [登录失败、Token 错误或权限不足](#登录失败token-错误或权限不足)

---

## 功能特色

- 🔒 为 Gin 提供简单的 JWT 认证
- 🔁 内置登录、刷新、登出处理器
- 🛡️ 可自定义认证、授权与 Claims
- 🍪 支持 Cookie 与 Header Token
- 📝 易于集成，API 清晰
- 🔐 符合 RFC 6749 规范的刷新令牌（OAuth 2.0 标准）
- 🗄️ 可插拔的刷新令牌存储（内存、Redis 客户端缓存）
- 🏭 直接生成 Token，无需 HTTP 中间件
- 📦 结构化 Token 类型与元数据

---

## 安全性注意事项

### 🔒 关键安全要求

> **⚠️ JWT 密钥安全**
>
> - **最低要求：** 使用至少 **256 位（32 字节）** 长度的密钥
> - **禁止使用：** 简单密码、字典词汇或可预测的模式
> - **建议：** 生成加密安全的随机密钥或使用 `RS256` 算法
> - **存储：** 将密钥存储在环境变量中，绝不硬编码在源码中
> - **漏洞：** 弱密钥易受暴力破解攻击（[jwt-cracker](https://github.com/lmammino/jwt-cracker)）

### 🛡️ 生产环境安全检查清单

- ✅ **仅限 HTTPS：** 生产环境中务必使用 HTTPS
- ✅ **强密钥：** 最少 256 位随机生成的密钥
- ✅ **Token 过期：** 设置适当的过期时间（建议：访问 Token 15-60 分钟）
- ✅ **安全 Cookie：** 启用 `SecureCookie`、`CookieHTTPOnly` 和适当的 `SameSite` 设置
- ✅ **环境变量：** 将敏感配置存储在环境变量中
- ✅ **输入验证：** 彻底验证所有认证输入

### 🔄 OAuth 2.0 安全标准

此库遵循 **RFC 6749 OAuth 2.0** 安全标准：

- **分离令牌：** 使用不同的不透明刷新令牌（非 JWT）以增强安全性
- **服务器端存储：** 刷新令牌在服务器端存储和验证
- **令牌轮替：** 每次使用时自动轮替刷新令牌
- **增强安全性：** 防止 JWT 刷新令牌漏洞和重放攻击

### 💡 安全配置示例

```go
// ❌ 不良：弱密钥、不安全设置
authMiddleware := &jwt.GinJWTMiddleware{
    Key:         []byte("weak"),           // 太短！
    Timeout:     time.Hour * 24,          // 太长！
    SecureCookie: false,                  // 生产环境不安全！
}

// ✅ 良好：强安全配置
authMiddleware := &jwt.GinJWTMiddleware{
    Key:            []byte(os.Getenv("JWT_SECRET")), // 来自环境变量
    Timeout:        time.Minute * 15,                // 短期访问令牌
    MaxRefresh:     time.Hour * 24 * 7,             // 1 周刷新有效期
    SecureCookie:   true,                           // 仅限 HTTPS
    CookieHTTPOnly: true,                           // 防止 XSS
    CookieSameSite: http.SameSiteStrictMode,        // CSRF 保护
    SendCookie:     true,                           // 启用安全 Cookie
}
```

**更多安全指导，请参见我们的 [安全最佳实践指南](_docs/security.md)**

---

## 安装

```go
import "github.com/appleboy/gin-jwt/v3"
```

---

## 快速开始示例

请参考 [`_example/basic/server.go`](./_example/basic/server.go) 示例文件，并可使用 `ExtractClaims` 获取 JWT 内的用户数据。

```go
// ...（完整示例请见 _example/basic/server.go）
```

---

## Token 生成器（直接创建 Token）

`TokenGenerator` 功能让你可以直接创建 JWT Token 而无需 HTTP 中间件，非常适合程序化认证、测试和自定义流程。

### 基本用法

```go
package main

import (
    "fmt"
    "log"
    "time"

    jwt "github.com/appleboy/gin-jwt/v3"
    gojwt "github.com/golang-jwt/jwt/v5"
)

func main() {
    // 初始化中间件
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

    // 生成完整的 Token 组（访问 + 刷新 Token）
    userData := "user123"
    tokenPair, err := authMiddleware.TokenGenerator(userData)
    if err != nil {
        log.Fatal("Failed to generate token pair:", err)
    }

    fmt.Printf("Access Token: %s\n", tokenPair.AccessToken)
    fmt.Printf("Refresh Token: %s\n", tokenPair.RefreshToken)
    fmt.Printf("Expires In: %d seconds\n", tokenPair.ExpiresIn())
}
```

### Token 结构

`TokenGenerator` 方法返回结构化的 `core.Token`：

```go
type Token struct {
    AccessToken  string `json:"access_token"`   // JWT 访问 Token
    TokenType    string `json:"token_type"`     // 总是 "Bearer"
    RefreshToken string `json:"refresh_token"`  // 不透明刷新 Token
    ExpiresAt    int64  `json:"expires_at"`     // Unix 时间戳
    CreatedAt    int64  `json:"created_at"`     // Unix 时间戳
}

// 辅助方法
func (t *Token) ExpiresIn() int64 // 返回到期前的秒数
```

### 刷新 Token 管理

使用 `TokenGeneratorWithRevocation` 来刷新 Token 并自动撤销旧 Token：

```go
// 刷新并自动撤销旧 Token
newTokenPair, err := authMiddleware.TokenGeneratorWithRevocation(userData, oldRefreshToken)
if err != nil {
    log.Fatal("Failed to refresh token:", err)
}

// 旧刷新 Token 现在已失效
fmt.Printf("New Access Token: %s\n", newTokenPair.AccessToken)
fmt.Printf("New Refresh Token: %s\n", newTokenPair.RefreshToken)
```

**使用场景：**

- 🔧 **程序化认证**：服务间通信
- 🧪 **测试**：为测试认证端点生成 Token
- 📝 **注册流程**：用户注册后立即发放 Token
- ⚙️ **后台作业**：为自动化流程创建 Token
- 🎛️ **自定义认证流程**：构建自定义认证逻辑

详见[完整示例](_example/token_generator/)。

---

## Redis 存储配置

此库支持 Redis 作为刷新令牌存储后端，并内置客户端缓存以提升性能。相比默认的内存存储，Redis 存储提供更好的可扩展性和持久性。

### Redis 功能特色

- 🔄 **客户端缓存**：内置 Redis 客户端缓存以提升性能
- 🚀 **自动回退**：Redis 连接失败时自动回退到内存存储
- ⚙️ **简易配置**：简单的方法配置 Redis 存储
- 🔧 **方法链**：流畅的 API，便于配置
- 📦 **工厂模式**：同时支持 Redis 和内存存储

### Redis 使用方法

#### 使用函数选项模式（推荐）

Redis 配置现在使用函数选项模式，提供更清洁且灵活的配置：

```go
// 方法 1：使用默认配置启用 Redis
middleware := &jwt.GinJWTMiddleware{
    // ... 其他配置
}.EnableRedisStore()

// 方法 2：使用自定义地址启用 Redis
middleware := &jwt.GinJWTMiddleware{
    // ... 其他配置
}.EnableRedisStore(
    jwt.WithRedisAddr("redis.example.com:6379"),
)

// 方法 3：使用认证启用 Redis
middleware := &jwt.GinJWTMiddleware{
    // ... 其他配置
}.EnableRedisStore(
    jwt.WithRedisAddr("redis.example.com:6379"),
    jwt.WithRedisAuth("password", 0),
)

// 方法 4：使用所有选项的完整配置
middleware := &jwt.GinJWTMiddleware{
    // ... 其他配置
}.EnableRedisStore(
    jwt.WithRedisAddr("redis.example.com:6379"),
    jwt.WithRedisAuth("password", 1),
    jwt.WithRedisCache(128*1024*1024, time.Minute),     // 128MB 缓存，1分钟 TTL
    jwt.WithRedisPool(20, time.Hour, 2*time.Hour),      // 连接池配置
    jwt.WithRedisKeyPrefix("myapp:jwt:"),               // 键前缀
)
```

#### 可用选项

- `WithRedisAddr(addr string)` - 设置 Redis 服务器地址
- `WithRedisAuth(password string, db int)` - 设置认证和数据库
- `WithRedisCache(size int, ttl time.Duration)` - 配置客户端缓存
- `WithRedisPool(poolSize int, maxIdleTime, maxLifetime time.Duration)` - 配置连接池
- `WithRedisKeyPrefix(prefix string)` - 设置 Redis 键的前缀

### 配置选项

#### RedisConfig

- **Addr**：Redis 服务器地址（默认：`"localhost:6379"`）
- **Password**：Redis 密码（默认：`""`）
- **DB**：Redis 数据库编号（默认：`0`）
- **CacheSize**：客户端缓存大小（字节）（默认：`128MB`）
- **CacheTTL**：客户端缓存 TTL（默认：`1 分钟`）
- **KeyPrefix**：所有 Redis 键的前缀（默认：`"gin-jwt:"`）

### 回退行为

如果在初始化期间 Redis 连接失败：

- 中间件会记录错误消息
- 自动回退到内存存储
- 应用程序继续正常运行

这确保了高可用性，防止因 Redis 连接问题导致的应用程序故障。

### Redis 示例

参见[Redis 示例](_example/redis_simple/)了解完整实现。

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
    }).EnableRedisStore(                                            // 使用选项启用 Redis
        jwt.WithRedisAddr("localhost:6379"),                       // Redis 服务器地址
        jwt.WithRedisCache(64*1024*1024, 30*time.Second),         // 64MB 缓存，30秒 TTL
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

---

## 理解 Authorizer

`Authorizer` 函数是在应用程序中实现基于角色的访问控制的关键组件。它决定已认证用户是否有权限访问特定的受保护路由。

### Authorizer 工作原理

`Authorizer` 在使用 `MiddlewareFunc()` 的任何路由的 JWT 中间件处理过程中**自动调用**。执行流程如下：

1. **Token 验证**：JWT 中间件验证 token
2. **身份提取**：`IdentityHandler` 从 token claims 中提取用户身份
3. **授权检查**：`Authorizer` 决定用户是否可以访问资源
4. **路由访问**：如果授权通过，请求继续；否则调用 `Unauthorized`

### Authorizer 函数签名

```go
func(c *gin.Context, data any) bool
```

- `c *gin.Context`：包含请求信息的 Gin 上下文
- `data any`：由 `IdentityHandler` 返回的用户身份数据
- 返回 `bool`：`true` 表示授权访问，`false` 表示拒绝访问

### 基本用法示例

#### 示例 1：基于角色的授权

```go
func authorizeHandler() func(c *gin.Context, data any) bool {
    return func(c *gin.Context, data any) bool {
        if v, ok := data.(*User); ok && v.UserName == "admin" {
            return true  // 只有 admin 用户可以访问
        }
        return false
    }
}
```

#### 示例 2：基于路径的授权

```go
func authorizeHandler() func(c *gin.Context, data any) bool {
    return func(c *gin.Context, data any) bool {
        user, ok := data.(*User)
        if !ok {
            return false
        }

        path := c.Request.URL.Path

        // Admin 可以访问所有路由
        if user.Role == "admin" {
            return true
        }

        // 普通用户只能访问 /auth/profile 和 /auth/hello
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

#### 示例 3：基于方法和路径的授权

```go
func authorizeHandler() func(c *gin.Context, data any) bool {
    return func(c *gin.Context, data any) bool {
        user, ok := data.(*User)
        if !ok {
            return false
        }

        path := c.Request.URL.Path
        method := c.Request.Method

        // 管理员拥有完全访问权限
        if user.Role == "admin" {
            return true
        }

        // 用户只能 GET 自己的资料
        if path == "/auth/profile" && method == "GET" {
            return true
        }

        // 用户不能修改或删除资源
        if method == "POST" || method == "PUT" || method == "DELETE" {
            return false
        }

        return true // 允许其他 GET 请求
    }
}
```

### 为不同路由设置不同授权

要为不同的路由组实现不同的授权规则，可以创建多个中间件实例或在单个 Authorizer 中使用路径检查：

#### 方法 1：多个中间件实例

```go
// 仅限管理员的中间件
adminMiddleware, _ := jwt.New(&jwt.GinJWTMiddleware{
    // ... 其他配置
    Authorizer: func(c *gin.Context, data any) bool {
        if user, ok := data.(*User); ok {
            return user.Role == "admin"
        }
        return false
    },
})

// 普通用户中间件
userMiddleware, _ := jwt.New(&jwt.GinJWTMiddleware{
    // ... 其他配置
    Authorizer: func(c *gin.Context, data any) bool {
        if user, ok := data.(*User); ok {
            return user.Role == "user" || user.Role == "admin"
        }
        return false
    },
})

// 路由设置
adminRoutes := r.Group("/admin", adminMiddleware.MiddlewareFunc())
userRoutes := r.Group("/user", userMiddleware.MiddlewareFunc())
```

#### 方法 2：带路径逻辑的单一 Authorizer

```go
func authorizeHandler() func(c *gin.Context, data any) bool {
    return func(c *gin.Context, data any) bool {
        user, ok := data.(*User)
        if !ok {
            return false
        }

        path := c.Request.URL.Path

        // 管理员路由 - 只允许管理员
        if strings.HasPrefix(path, "/admin/") {
            return user.Role == "admin"
        }

        // 用户路由 - 允许用户和管理员
        if strings.HasPrefix(path, "/user/") {
            return user.Role == "user" || user.Role == "admin"
        }

        // 公开认证路由 - 所有已认证用户
        return true
    }
}
```

### 高级授权模式

#### 使用 Claims 进行细粒度控制

```go
func authorizeHandler() func(c *gin.Context, data any) bool {
    return func(c *gin.Context, data any) bool {
        // 提取额外的 claims
        claims := jwt.ExtractClaims(c)

        // 从 claims 获取用户权限
        permissions, ok := claims["permissions"].([]interface{})
        if !ok {
            return false
        }

        // 检查用户是否拥有此路由所需的权限
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

### 常见模式和最佳实践

1. **始终验证数据类型**：检查用户数据是否可以转换为您期望的类型
2. **使用 claims 获取额外上下文**：使用 `jwt.ExtractClaims(c)` 访问 JWT claims
3. **考虑请求上下文**：使用 `c.Request.URL.Path`、`c.Request.Method` 等
4. **安全优先**：默认返回 `false`，显式允许访问
5. **记录授权失败**：添加日志以调试授权问题

### 完整示例

查看[授权示例](_example/authorization/)了解展示不同授权场景的完整实现。

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
  将认证通过的用户数据转为 `MapClaims`（map[string]any），必须包含 `IdentityKey`（默认 `"identity"`）。

- **可选：** `LoginResponse`
  在成功验证后处理登录后逻辑。此函数接收完整的 token 信息（包括访问 token、刷新 token、过期时间等）作为结构化的 `core.Token` 对象，用于处理登录后逻辑并返回 token 响应给用户。

  函数签名：`func(c *gin.Context, token *core.Token)`

---

### 需要 JWT Token 的端点（MiddlewareFunc）

- **内置：** `MiddlewareFunc`  
  用于需要 JWT 认证的端点。会：

  - 从 header/cookie/query 解析 Token
  - 验证 Token
  - 调用 `IdentityHandler` 与 `Authorizer`
  - 验证失败则调用 `Unauthorized`

- **可选：** `IdentityHandler`  
  从 JWT Claims 获取用户身份。

- **可选：** `Authorizer`  
  检查用户是否有权限访问该端点。

---

### 登出流程（LogoutHandler）

- **内置：** `LogoutHandler`  
  用于登出端点。会清除 Cookie（若 `SendCookie` 设置为 true）并调用 `LogoutResponse`。

- **可选：** `LogoutResponse`
  在登出处理完成后调用此函数。应返回适当的 HTTP 响应以表示登出成功或失败。由于登出不会生成新的 token，此函数只接收 gin context。

  函数签名：`func(c *gin.Context)`

---

### 刷新流程（RefreshHandler）

- **内置：** `RefreshHandler`  
  用于刷新 Token 端点。若 Token 在 `MaxRefreshTime` 内，会发新 Token 并调用 `RefreshResponse`。

- **可选：** `RefreshResponse`
  在成功刷新 token 后调用此函数。接收完整的新 token 信息作为结构化的 `core.Token` 对象，应返回包含新 `access_token`、`token_type`、`expires_in` 和 `refresh_token` 字段的 JSON 响应，遵循 RFC 6749 token 响应格式。

  函数签名：`func(c *gin.Context, token *core.Token)`

---

### 登录失败、Token 错误或权限不足

- **可选：** `Unauthorized`  
  处理登录、授权或 Token 错误时的响应。返回 HTTP 错误码与消息的 JSON。
