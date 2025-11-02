package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/appleboy/gin-jwt/v3"
	"github.com/gin-gonic/gin"
	gojwt "github.com/golang-jwt/jwt/v5"
)

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

var (
	identityKey = "id"
	roleKey     = "role"
	port        string
)

type User struct {
	UserName string
	Role     string
}

func init() {
	port = os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
}

func main() {
	engine := gin.Default()

	// Create middleware with comprehensive authorizer
	authMiddleware, err := jwt.New(initParams())
	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	// Initialize middleware
	errInit := authMiddleware.MiddlewareInit()
	if errInit != nil {
		log.Fatal("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
	}

	// Register routes
	registerRoutes(engine, authMiddleware)

	log.Printf("Server starting on port %s", port)
	log.Println("Available users:")
	log.Println("  admin/admin (role: admin)")
	log.Println("  user/user   (role: user)")
	log.Println("  guest/guest (role: guest)")

	// Start server
	if err = http.ListenAndServe(":"+port, engine); err != nil {
		log.Fatal(err)
	}
}

func registerRoutes(r *gin.Engine, authMiddleware *jwt.GinJWTMiddleware) {
	// Public routes
	r.POST("/login", authMiddleware.LoginHandler)
	r.POST("/refresh", authMiddleware.RefreshHandler)

	// Public info endpoint
	r.GET("/info", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Authorization Example API",
			"users": gin.H{
				"admin": gin.H{"password": "admin", "role": "admin", "access": "All routes"},
				"user": gin.H{
					"password": "user",
					"role":     "user",
					"access":   "/user/* and /auth/profile",
				},
				"guest": gin.H{"password": "guest", "role": "guest", "access": "/auth/hello only"},
			},
			"routes": gin.H{
				"public": []string{"/login", "/refresh", "/info"},
				"admin":  []string{"/admin/users", "/admin/settings", "/admin/reports"},
				"user":   []string{"/user/profile", "/user/settings"},
				"auth":   []string{"/auth/hello", "/auth/profile", "/auth/logout"},
			},
		})
	})

	// Admin routes - only admin role can access
	adminRoutes := r.Group("/admin", authMiddleware.MiddlewareFunc())
	{
		adminRoutes.GET("/users", adminUsersHandler)
		adminRoutes.GET("/settings", adminSettingsHandler)
		adminRoutes.GET("/reports", adminReportsHandler)
		adminRoutes.POST("/users", createUserHandler)
		adminRoutes.DELETE("/users/:id", deleteUserHandler)
	}

	// User routes - user and admin roles can access
	userRoutes := r.Group("/user", authMiddleware.MiddlewareFunc())
	{
		userRoutes.GET("/profile", userProfileHandler)
		userRoutes.PUT("/profile", updateProfileHandler)
		userRoutes.GET("/settings", userSettingsHandler)
	}

	// General auth routes - different permissions based on path
	authRoutes := r.Group("/auth", authMiddleware.MiddlewareFunc())
	{
		authRoutes.GET("/hello", helloHandler)                   // All authenticated users
		authRoutes.GET("/profile", profileHandler)               // User and admin only
		authRoutes.POST("/logout", authMiddleware.LogoutHandler) // User Logout
		authRoutes.GET("/whoami", whoAmIHandler)                 // All authenticated users
	}
}

func initParams() *jwt.GinJWTMiddleware {
	return &jwt.GinJWTMiddleware{
		Realm:       "authorization example",
		Key:         []byte("secret key"),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: identityKey,
		PayloadFunc: payloadFunc(),

		IdentityHandler: identityHandler(),
		Authenticator:   authenticator(),
		Authorizer:      authorizator(),
		Unauthorized:    unauthorized(),
		TokenLookup:     "header: Authorization, query: token, cookie: jwt",
		TokenHeadName:   "Bearer",
		TimeFunc:        time.Now,
	}
}

func payloadFunc() func(data any) gojwt.MapClaims {
	return func(data any) gojwt.MapClaims {
		if v, ok := data.(*User); ok {
			return gojwt.MapClaims{
				identityKey: v.UserName,
				roleKey:     v.Role,
			}
		}
		return gojwt.MapClaims{}
	}
}

func identityHandler() func(c *gin.Context) any {
	return func(c *gin.Context) any {
		claims := jwt.ExtractClaims(c)
		role, _ := claims[roleKey].(string)
		return &User{
			UserName: claims[identityKey].(string),
			Role:     role,
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

		// Define users with their roles
		users := map[string]map[string]string{
			"admin": {"password": "admin", "role": "admin"},
			"user":  {"password": "user", "role": "user"},
			"guest": {"password": "guest", "role": "guest"},
		}

		if userData, exists := users[userID]; exists && userData["password"] == password {
			return &User{
				UserName: userID,
				Role:     userData["role"],
			}, nil
		}

		return nil, jwt.ErrFailedAuthentication
	}
}

// Comprehensive authorizer that demonstrates different authorization patterns
func authorizator() func(c *gin.Context, data any) bool {
	return func(c *gin.Context, data any) bool {
		user, ok := data.(*User)
		if !ok {
			return false
		}

		path := c.Request.URL.Path
		method := c.Request.Method

		log.Printf("Authorization check - User: %s, Role: %s, Path: %s, Method: %s",
			user.UserName, user.Role, path, method)

		// Admin has access to everything
		if user.Role == "admin" {
			return true
		}

		// Admin routes - only admin allowed (already handled above, but explicit for clarity)
		if strings.HasPrefix(path, "/admin/") {
			return user.Role == "admin"
		}

		// User routes - user and admin roles allowed
		if strings.HasPrefix(path, "/user/") {
			return user.Role == "user" || user.Role == "admin"
		}

		// Auth routes with specific rules
		if strings.HasPrefix(path, "/auth/") {
			switch path {
			case "/auth/hello", "/auth/whoami", "/auth/logout":
				// All authenticated users can access
				return true
			case "/auth/profile":
				// Only user and admin roles
				return user.Role == "user" || user.Role == "admin"
			}
		}

		// Default: deny access
		return false
	}
}

func unauthorized() func(c *gin.Context, code int, message string) {
	return func(c *gin.Context, code int, message string) {
		c.JSON(code, gin.H{
			"code":    code,
			"message": message,
			"path":    c.Request.URL.Path,
			"method":  c.Request.Method,
		})
	}
}

// Handler functions
func adminUsersHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "Admin Users Management",
		"users":   []string{"admin", "user1", "user2", "guest1"},
		"access":  "admin only",
	})
}

func adminSettingsHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"message":  "Admin Settings",
		"settings": gin.H{"max_users": 100, "allow_registration": true},
		"access":   "admin only",
	})
}

func adminReportsHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "Admin Reports",
		"reports": []string{"daily_usage", "user_activity", "system_health"},
		"access":  "admin only",
	})
}

func createUserHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "User created successfully",
		"access":  "admin only",
	})
}

func deleteUserHandler(c *gin.Context) {
	userID := c.Param("id")
	c.JSON(200, gin.H{
		"message": "User deleted successfully",
		"user_id": userID,
		"access":  "admin only",
	})
}

func userProfileHandler(c *gin.Context) {
	user, _ := c.Get(identityKey)
	c.JSON(200, gin.H{
		"message":  "User Profile",
		"username": user.(*User).UserName,
		"role":     user.(*User).Role,
		"access":   "user and admin only",
	})
}

func updateProfileHandler(c *gin.Context) {
	user, _ := c.Get(identityKey)
	c.JSON(200, gin.H{
		"message":  "Profile updated successfully",
		"username": user.(*User).UserName,
		"access":   "user and admin only",
	})
}

func userSettingsHandler(c *gin.Context) {
	user, _ := c.Get(identityKey)
	c.JSON(200, gin.H{
		"message":  "User Settings",
		"username": user.(*User).UserName,
		"settings": gin.H{"theme": "dark", "notifications": true},
		"access":   "user and admin only",
	})
}

func helloHandler(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	user, _ := c.Get(identityKey)
	c.JSON(200, gin.H{
		"message":  "Hello World!",
		"userID":   claims[identityKey],
		"userName": user.(*User).UserName,
		"role":     user.(*User).Role,
		"access":   "all authenticated users",
	})
}

func profileHandler(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	user, _ := c.Get(identityKey)
	c.JSON(200, gin.H{
		"message":  "Profile Information",
		"userID":   claims[identityKey],
		"userName": user.(*User).UserName,
		"role":     user.(*User).Role,
		"access":   "user and admin roles only",
	})
}

func whoAmIHandler(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	user, _ := c.Get(identityKey)
	c.JSON(200, gin.H{
		"identity": claims[identityKey],
		"role":     claims[roleKey],
		"user":     user.(*User),
		"claims":   claims,
		"access":   "all authenticated users",
	})
}
