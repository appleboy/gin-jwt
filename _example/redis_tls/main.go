package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"time"

	jwt "github.com/appleboy/gin-jwt/v3"
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

		PayloadFunc: func(data any) gojwt.MapClaims {
			if v, ok := data.(*User); ok {
				return gojwt.MapClaims{
					identityKey: v.UserName,
				}
			}
			return gojwt.MapClaims{}
		},

		IdentityHandler: func(c *gin.Context) any {
			claims := jwt.ExtractClaims(c)
			return &User{
				UserName: claims[identityKey].(string),
			}
		},

		Authenticator: func(c *gin.Context) (any, error) {
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

		Authorizer: func(c *gin.Context, data any) bool {
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

	// Configure TLS for secure Redis connection
	tlsConfig := createTLSConfig()

	// Configure Redis store with TLS enabled
	middleware.EnableRedisStore(
		jwt.WithRedisAddr("redis.example.com:6380"), // Use TLS port (usually 6380)
		jwt.WithRedisAuth("your-password", 0),
		jwt.WithRedisTLS(tlsConfig),
		jwt.WithRedisCache(64*1024*1024, 30*time.Second), // 64MB cache, 30s TTL
	)

	// Create the JWT middleware
	authMiddleware, err := jwt.New(middleware)
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
	log.Println("Redis TLS store is enabled")
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

// createTLSConfig creates a TLS configuration for Redis connection
func createTLSConfig() *tls.Config {
	// Example 1: Basic TLS with system CA certificates
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	// Example 2: TLS with custom CA certificate (uncomment to use)
	// caCert, err := os.ReadFile("/path/to/ca.crt")
	// if err != nil {
	// 	log.Fatalf("Failed to read CA certificate: %v", err)
	// }
	//
	// caCertPool := x509.NewCertPool()
	// if !caCertPool.AppendCertsFromPEM(caCert) {
	// 	log.Fatal("Failed to parse CA certificate")
	// }
	//
	// tlsConfig.RootCAs = caCertPool

	// Example 3: TLS with client certificate (mutual TLS) (uncomment to use)
	// cert, err := tls.LoadX509KeyPair("/path/to/client.crt", "/path/to/client.key")
	// if err != nil {
	// 	log.Fatalf("Failed to load client certificate: %v", err)
	// }
	//
	// tlsConfig.Certificates = []tls.Certificate{cert}

	// Example 4: Skip certificate verification (NOT recommended for production)
	// tlsConfig.InsecureSkipVerify = true

	return tlsConfig
}

// Example helper function to load custom CA certificate
func loadCACertificate(caPath string) *x509.CertPool {
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to parse CA certificate")
	}

	return caCertPool
}

// Example helper function to load client certificate for mutual TLS
func loadClientCertificate(certPath, keyPath string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("Failed to load client certificate: %v", err)
	}
	return cert
}
