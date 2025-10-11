package main

import (
	"log"
	"net/http"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	gojwt "github.com/golang-jwt/jwt/v5"
)

type User struct {
	UserName  string `json:"username"`
	Password  string `json:"password"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
}

var identityKey = "id"

func main() {
	r := gin.Default()

	// Create JWT middleware configuration
	middleware := &jwt.GinJWTMiddleware{
		Realm:       "test zone",
		Key:         []byte("secret key"),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: identityKey,

		PayloadFunc: func(data interface{}) gojwt.MapClaims {
			if v, ok := data.(*User); ok {
				return gojwt.MapClaims{
					identityKey: v.UserName,
				}
			}
			return gojwt.MapClaims{}
		},

		IdentityHandler: func(c *gin.Context) interface{} {
			claims := jwt.ExtractClaims(c)
			return &User{
				UserName: claims[identityKey].(string),
			}
		},

		Authenticator: func(c *gin.Context) (interface{}, error) {
			var loginVals User
			if err := c.ShouldBind(&loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}
			userID := loginVals.UserName
			password := loginVals.Password

			if (userID == "admin" && password == "admin") || (userID == "test" && password == "test") {
				return &User{
					UserName:  userID,
					LastName:  "Bo-Yi",
					FirstName: "Wu",
				}, nil
			}

			return nil, jwt.ErrFailedAuthentication
		},

		Authorizator: func(data interface{}, c *gin.Context) bool {
			if v, ok := data.(*User); ok && v.UserName == "admin" {
				return true
			}
			return false
		},

		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		},

		TokenLookup:   "header: Authorization, query: token, cookie: jwt",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	}

	// Configure Redis store using convenience methods
	middleware.EnableRedisStore().SetRedisClientSideCache(64*1024*1024, 30*time.Second) // 64MB cache, 30s TTL

	// Create the JWT middleware
	authMiddleware, err := jwt.New(middleware)

	// Alternative initialization methods:
	//
	// Method 1: Simple enable with defaults
	// }.EnableRedisStore())
	//
	// Method 2: Enable with custom address
	// }.EnableRedisStoreWithAddr("redis:6379"))
	//
	// Method 3: Enable with full options
	// }.EnableRedisStoreWithOptions("localhost:6379", "", 0))
	//
	// Method 4: Enable with custom config
	// config := store.DefaultRedisConfig()
	// config.Addr = "localhost:6379"
	// config.CacheSize = 128 * 1024 * 1024 // 128MB
	// }.EnableRedisStoreWithConfig(config))

	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	// When you use jwt.New(), the function is already automatically called for checking,
	// which means you don't need to call it again.
	errInit := authMiddleware.MiddlewareInit()
	if errInit != nil {
		log.Fatal("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
	}

	r.POST("/login", authMiddleware.LoginHandler)

	r.NoRoute(authMiddleware.MiddlewareFunc(), func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		log.Printf("NoRoute claims: %#v\n", claims)
		c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
	})

	auth := r.Group("/auth")
	// Refresh time can be longer than token timeout
	auth.GET("/refresh_token", authMiddleware.RefreshHandler)
	auth.Use(authMiddleware.MiddlewareFunc())
	{
		auth.GET("/hello", helloHandler)
	}

	log.Println("Server starting on :8000")
	log.Println("Redis store is enabled - will fall back to memory if Redis is not available")
	if err := http.ListenAndServe(":8000", r); err != nil {
		log.Fatal(err)
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