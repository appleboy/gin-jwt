package main

import (
	"log"
	"net/http"
	"os"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	gojwt "github.com/golang-jwt/jwt/v5"
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
		Authorizator:    authorizator(),
		Unauthorized:    unauthorized(),
		LogoutResponse:  logoutResponse(),
		TokenLookup:     "header: Authorization, query: token, cookie: jwt",
		// TokenLookup: "query:token",
		// TokenLookup: "cookie:token",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	}
}

func payloadFunc() func(data any) gojwt.MapClaims {
	return func(data any) gojwt.MapClaims {
		if v, ok := data.(*User); ok {
			return gojwt.MapClaims{
				identityKey: v.UserName,
			}
		}
		return gojwt.MapClaims{}
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

func authorizator() func(data any, c *gin.Context) bool {
	return func(data any, c *gin.Context) bool {
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

func logoutResponse() func(c *gin.Context, code int) {
	return func(c *gin.Context, code int) {
		// This demonstrates that claims are now accessible during logout
		claims := jwt.ExtractClaims(c)
		user, exists := c.Get(identityKey)

		response := gin.H{
			"code":    code,
			"message": "Successfully logged out",
		}

		// Show that we can access user information during logout
		if len(claims) > 0 {
			response["logged_out_user"] = claims[identityKey]
		}
		if exists {
			response["user_info"] = user.(*User).UserName
		}

		c.JSON(code, response)
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
