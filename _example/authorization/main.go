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

const (
	passwordKey     = "password"
	messageKey      = "message"
	accessKey       = "access"
	userRole        = "user"
	guestRole       = "guest"
	adminAccess     = "admin only"
	usernameKey     = "username"
	userAdminAccess = "user and admin only"
)

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

const roleAdmin = "admin"

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

	// Start server with proper timeouts
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           engine,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err = srv.ListenAndServe(); err != nil {
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
			messageKey: "Authorization Example API",
			"users": gin.H{
				roleAdmin: gin.H{
					passwordKey: roleAdmin,
					roleKey:     roleAdmin,
					accessKey:   "All routes",
				},
				userRole: gin.H{
					passwordKey: userRole,
					roleKey:     userRole,
					accessKey:   "/user/* and /auth/profile",
				},
				guestRole: gin.H{
					passwordKey: guestRole,
					roleKey:     guestRole,
					accessKey:   "/auth/hello only",
				},
			},
			"routes": gin.H{
				"public":  []string{"/login", "/refresh", "/info"},
				roleAdmin: []string{"/admin/users", "/admin/settings", "/admin/reports"},
				userRole:  []string{"/user/profile", "/user/settings"},
				"auth":    []string{"/auth/hello", "/auth/profile", "/auth/logout"},
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
			roleAdmin: {passwordKey: roleAdmin, roleKey: roleAdmin},
			userRole:  {passwordKey: userRole, roleKey: userRole},
			guestRole: {passwordKey: guestRole, roleKey: guestRole},
		}

		if userData, exists := users[userID]; exists && userData[passwordKey] == password {
			return &User{
				UserName: userID,
				Role:     userData[roleKey],
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
		if user.Role == roleAdmin {
			return true
		}

		// Admin routes - only admin allowed (already handled above, but explicit for clarity)
		if strings.HasPrefix(path, "/admin/") {
			return user.Role == roleAdmin
		}

		// User routes - user and admin roles allowed
		if strings.HasPrefix(path, "/user/") {
			return user.Role == userRole || user.Role == roleAdmin
		}

		// Auth routes with specific rules
		if strings.HasPrefix(path, "/auth/") {
			switch path {
			case "/auth/hello", "/auth/whoami", "/auth/logout":
				// All authenticated users can access
				return true
			case "/auth/profile":
				// Only user and admin roles
				return user.Role == userRole || user.Role == roleAdmin
			}
		}

		// Default: deny access
		return false
	}
}

func unauthorized() func(c *gin.Context, code int, message string) {
	return func(c *gin.Context, code int, message string) {
		c.JSON(code, gin.H{
			"code":     code,
			messageKey: message,
			"path":     c.Request.URL.Path,
			"method":   c.Request.Method,
		})
	}
}

// Handler functions
func adminUsersHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		messageKey: "Admin Users Management",
		"users":    []string{roleAdmin, "user1", "user2", "guest1"},
		accessKey:  adminAccess,
	})
}

func adminSettingsHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		messageKey: "Admin Settings",
		"settings": gin.H{"max_users": 100, "allow_registration": true},
		accessKey:  adminAccess,
	})
}

func adminReportsHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		messageKey: "Admin Reports",
		"reports":  []string{"daily_usage", "user_activity", "system_health"},
		accessKey:  adminAccess,
	})
}

func createUserHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		messageKey: "User created successfully",
		accessKey:  adminAccess,
	})
}

func deleteUserHandler(c *gin.Context) {
	userID := c.Param("id")
	c.JSON(200, gin.H{
		messageKey: "User deleted successfully",
		"user_id":  userID,
		accessKey:  adminAccess,
	})
}

func userProfileHandler(c *gin.Context) {
	user, _ := c.Get(identityKey)
	c.JSON(200, gin.H{
		messageKey:  "User Profile",
		usernameKey: user.(*User).UserName,
		roleKey:     user.(*User).Role,
		accessKey:   userAdminAccess,
	})
}

func updateProfileHandler(c *gin.Context) {
	user, _ := c.Get(identityKey)
	c.JSON(200, gin.H{
		messageKey:  "Profile updated successfully",
		usernameKey: user.(*User).UserName,
		accessKey:   userAdminAccess,
	})
}

func userSettingsHandler(c *gin.Context) {
	user, _ := c.Get(identityKey)
	c.JSON(200, gin.H{
		messageKey:  "User Settings",
		usernameKey: user.(*User).UserName,
		"settings":  gin.H{"theme": "dark", "notifications": true},
		accessKey:   userAdminAccess,
	})
}

func helloHandler(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	user, _ := c.Get(identityKey)
	c.JSON(200, gin.H{
		messageKey: "Hello World!",
		"userID":   claims[identityKey],
		"userName": user.(*User).UserName,
		roleKey:    user.(*User).Role,
		accessKey:  "all authenticated users",
	})
}

func profileHandler(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	user, _ := c.Get(identityKey)
	c.JSON(200, gin.H{
		messageKey: "Profile Information",
		"userID":   claims[identityKey],
		"userName": user.(*User).UserName,
		roleKey:    user.(*User).Role,
		accessKey:  "user and admin roles only",
	})
}

func whoAmIHandler(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	user, _ := c.Get(identityKey)
	c.JSON(200, gin.H{
		"identity": claims[identityKey],
		roleKey:    claims[roleKey],
		userRole:   user.(*User),
		"claims":   claims,
		accessKey:  "all authenticated users",
	})
}
