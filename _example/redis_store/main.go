package main

import (
	"log"
	"net/http"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/appleboy/gin-jwt/v2/store"

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
	// Create Redis store with client-side cache
	redisConfig := store.DefaultRedisConfig()
	redisConfig.Addr = "localhost:6379"      // Change this to your Redis server
	redisConfig.CacheSize = 64 * 1024 * 1024 // 64MB client-side cache
	redisConfig.CacheTTL = 30 * time.Second  // Cache TTL

	// Create store using factory pattern - defaults to memory if Redis fails
	var tokenStore store.RefreshTokenStorer

	// Try to create Redis store first
	config := store.NewRedisConfig(redisConfig)
	redisStore, err := store.NewStore(config)
	if err != nil {
		log.Printf("Failed to connect to Redis: %v, falling back to memory store", err)
		// Fall back to memory store
		tokenStore = store.Default()
	} else {
		log.Println("Connected to Redis successfully with client-side cache enabled")
		tokenStore = redisStore
	}

	// Or you can use the factory pattern directly:
	// tokenStore := store.MustNewStore(store.NewMemoryConfig()) // Memory store
	// tokenStore := store.MustNewRedisStore(redisConfig)        // Redis store (panics on failure)

	r := gin.Default()

	// the jwt middleware
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
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
		RefreshTokenStore: tokenStore, // Use our Redis or memory store
		TokenLookup:       "header: Authorization, query: token, cookie: jwt",
		TokenHeadName:     "Bearer",
		TimeFunc:          time.Now,
	})
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
		auth.GET("/store-info", storeInfoHandler(tokenStore))
	}

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

// storeInfoHandler provides information about the current token store
func storeInfoHandler(tokenStore store.RefreshTokenStorer) gin.HandlerFunc {
	return func(c *gin.Context) {
		count, err := tokenStore.Count()
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		storeType := "unknown"
		switch tokenStore.(type) {
		case *store.InMemoryRefreshTokenStore:
			storeType = "memory"
		case *store.RedisRefreshTokenStore:
			storeType = "redis"
		}

		c.JSON(200, gin.H{
			"store_type":  storeType,
			"token_count": count,
			"message":     "Token store information",
		})
	}
}
