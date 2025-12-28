package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	jwt "github.com/appleboy/gin-jwt/v3"
	"github.com/appleboy/gin-jwt/v3/core"
	"github.com/gin-gonic/gin"
	gojwt "github.com/golang-jwt/jwt/v5"
	_ "github.com/joho/godotenv/autoload"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

const identityKey = "id"

var (
	port              string
	googleOauthConfig *oauth2.Config
	githubOauthConfig *oauth2.Config
	// Store OAuth state tokens to prevent CSRF attacks
	oauthStateStore = make(map[string]time.Time)
)

// User represents the user information from OAuth provider
type User struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	AvatarURL string `json:"avatar_url,omitempty"`
}

// GoogleUserInfo represents Google user information
type GoogleUserInfo struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

// GitHubUserInfo represents GitHub user information
type GitHubUserInfo struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

func init() {
	port = os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	// Google OAuth2 Configuration
	googleOauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  fmt.Sprintf("http://localhost:%s/auth/google/callback", port),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	// GitHub OAuth2 Configuration
	githubOauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		RedirectURL:  fmt.Sprintf("http://localhost:%s/auth/github/callback", port),
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}

	// Clean up expired state tokens every 10 minutes
	go cleanupExpiredStates()
}

func main() {
	// Validate OAuth configuration
	if googleOauthConfig.ClientID == "" && githubOauthConfig.ClientID == "" {
		log.Println(
			"Warning: No OAuth providers configured. Set GOOGLE_CLIENT_ID/SECRET or GITHUB_CLIENT_ID/SECRET",
		)
	}

	engine := gin.Default()

	// Initialize JWT middleware
	authMiddleware, err := jwt.New(initJWTParams())
	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	if err := authMiddleware.MiddlewareInit(); err != nil {
		log.Fatal("authMiddleware.MiddlewareInit() Error:" + err.Error())
	}

	// Register routes
	registerRoute(engine, authMiddleware)

	// Start HTTP server
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           engine,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("Server starting on http://localhost:%s", port)
	log.Printf("Demo Page: http://localhost:%s/demo", port)
	log.Println("\nOAuth Login URLs:")
	if googleOauthConfig.ClientID != "" {
		log.Printf("  Google: http://localhost:%s/auth/google/login", port)
	}
	if githubOauthConfig.ClientID != "" {
		log.Printf("  GitHub: http://localhost:%s/auth/github/login", port)
	}
	if googleOauthConfig.ClientID == "" && githubOauthConfig.ClientID == "" {
		log.Println("  (No OAuth providers configured)")
	}

	if err = srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func registerRoute(r *gin.Engine, handle *jwt.GinJWTMiddleware) {
	// Enable CORS for development
	r.Use(corsMiddleware())

	// Public routes
	r.GET("/", indexHandler)
	r.StaticFile("/demo", "./index.html")

	// OAuth login initiation
	r.GET("/auth/google/login", handleGoogleLogin)
	r.GET("/auth/github/login", handleGitHubLogin)

	// OAuth callbacks
	r.GET("/auth/google/callback", handleGoogleCallback(handle))
	r.GET("/auth/github/callback", handleGitHubCallback(handle))

	// JWT token refresh
	r.POST("/auth/refresh", handle.RefreshHandler)

	// Protected routes
	auth := r.Group("/api", handle.MiddlewareFunc())
	{
		auth.GET("/profile", profileHandler)
		auth.POST("/logout", handle.LogoutHandler)
	}

	r.NoRoute(handle.MiddlewareFunc(), handleNoRoute())
}

func initJWTParams() *jwt.GinJWTMiddleware {
	return &jwt.GinJWTMiddleware{
		Realm:       "oauth-sso-zone",
		Key:         []byte(getSecretKey()),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour * 24,
		IdentityKey: identityKey,
		PayloadFunc: payloadFunc(),

		IdentityHandler: identityHandler(),
		Authenticator:   authenticator(),
		Authorizer:      authorizer(),
		Unauthorized:    unauthorized(),
		LogoutResponse:  logoutResponse(),
		TokenLookup:     "header: Authorization, query: token, cookie: jwt",
		TokenHeadName:   "Bearer",
		TimeFunc:        time.Now,

		// Enable built-in cookie support for better security
		SendCookie:        true,
		SecureCookie:      false, // Set to true in production with HTTPS
		CookieHTTPOnly:    true,
		CookieMaxAge:      time.Hour,
		CookieDomain:      "",
		SendAuthorization: true, // Send Authorization header in LoginResponse

		// Custom LoginResponse to handle OAuth redirect vs regular JSON response
		LoginResponse: func(c *gin.Context, token *core.Token) {
			provider, isOAuth := c.Get("oauth_provider")
			if isOAuth {
				// OAuth: redirect to demo page (token already set in cookie by gin-jwt)
				redirectURL := fmt.Sprintf("/demo?provider=%s", provider)
				c.Redirect(http.StatusFound, redirectURL)
				return
			}

			// Regular login: return JSON response
			c.JSON(http.StatusOK, gin.H{
				"code":          http.StatusOK,
				"access_token":  token.AccessToken,
				"token_type":    token.TokenType,
				"refresh_token": token.RefreshToken,
				"expires_at":    token.ExpiresAt,
			})
		},
	}
}

func getSecretKey() string {
	key := os.Getenv("JWT_SECRET_KEY")
	if key == "" {
		key = "default-secret-key-change-in-production"
	}
	return key
}

func payloadFunc() func(data any) gojwt.MapClaims {
	return func(data any) gojwt.MapClaims {
		if v, ok := data.(*User); ok {
			return gojwt.MapClaims{
				identityKey: v.ID,
				"email":     v.Email,
				"name":      v.Name,
				"provider":  v.Provider,
				"avatar":    v.AvatarURL,
			}
		}
		return gojwt.MapClaims{}
	}
}

func identityHandler() func(c *gin.Context) any {
	return func(c *gin.Context) any {
		claims := jwt.ExtractClaims(c)
		return &User{
			ID:        claims[identityKey].(string),
			Email:     getStringFromClaims(claims, "email"),
			Name:      getStringFromClaims(claims, "name"),
			Provider:  getStringFromClaims(claims, "provider"),
			AvatarURL: getStringFromClaims(claims, "avatar"),
		}
	}
}

func authenticator() func(c *gin.Context) (any, error) {
	return func(c *gin.Context) (any, error) {
		// This is not used for OAuth flow, but required by the middleware
		// OAuth authentication happens in the callback handlers
		return nil, jwt.ErrMissingLoginValues
	}
}

func authorizer() func(c *gin.Context, data any) bool {
	return func(c *gin.Context, data any) bool {
		// All authenticated OAuth users are authorized
		if _, ok := data.(*User); ok {
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
		claims := jwt.ExtractClaims(c)
		c.JSON(http.StatusOK, gin.H{
			"code":    http.StatusOK,
			"message": "Successfully logged out",
			"user":    claims["email"],
		})
	}
}

// handleOAuthSuccess handles the successful OAuth authentication
// and uses gin-jwt's built-in features (SendCookie, LoginResponse, etc.)
func handleOAuthSuccess(
	c *gin.Context,
	authMiddleware *jwt.GinJWTMiddleware,
	user *User,
	provider string,
) error {
	// Set user identity in context (for middleware callbacks)
	c.Set(authMiddleware.IdentityKey, user)
	c.Set("oauth_provider", provider)

	// Generate JWT token
	token, err := authMiddleware.TokenGenerator(c.Request.Context(), user)
	if err != nil {
		return err
	}

	// Set cookies (both access token and refresh token)
	authMiddleware.SetCookie(c, token.AccessToken)
	authMiddleware.SetRefreshTokenCookie(c, token.RefreshToken)

	// Let gin-jwt handle everything (cookies, headers, response) via LoginResponse
	// The middleware will automatically:
	// - Set httpOnly cookie (if SendCookie is enabled)
	// - Set Authorization header (if SendAuthorization is enabled)
	// - Call LoginResponse callback (defined in initJWTParams)
	if authMiddleware.LoginResponse != nil {
		authMiddleware.LoginResponse(c, token)
	}

	return nil
}

// OAuth handlers
func handleGoogleLogin(c *gin.Context) {
	if googleOauthConfig.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Google OAuth not configured"})
		return
	}

	state := generateStateToken()
	url := googleOauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func handleGitHubLogin(c *gin.Context) {
	if githubOauthConfig.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "GitHub OAuth not configured"})
		return
	}

	state := generateStateToken()
	url := githubOauthConfig.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func handleGoogleCallback(authMiddleware *jwt.GinJWTMiddleware) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Validate state token (CSRF protection)
		state := c.Query("state")
		if !validateStateToken(state) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state token"})
			return
		}

		// Exchange authorization code for access token
		code := c.Query("code")
		token, err := googleOauthConfig.Exchange(context.Background(), code)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange token"})
			return
		}

		// Get user info from Google
		client := googleOauthConfig.Client(context.Background(), token)
		resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
			return
		}
		defer resp.Body.Close()

		data, _ := io.ReadAll(resp.Body)
		var googleUser GoogleUserInfo
		if err := json.Unmarshal(data, &googleUser); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse user info"})
			return
		}

		// Create user object
		user := &User{
			ID:        "google_" + googleUser.ID,
			Email:     googleUser.Email,
			Name:      googleUser.Name,
			Provider:  "google",
			AvatarURL: googleUser.Picture,
		}

		// Handle OAuth success with proper JWT middleware integration
		if err := handleOAuthSuccess(c, authMiddleware, user, "google"); err != nil {
			c.JSON(
				http.StatusInternalServerError,
				gin.H{"error": "Failed to complete authentication"},
			)
			return
		}
	}
}

func handleGitHubCallback(authMiddleware *jwt.GinJWTMiddleware) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Validate state token (CSRF protection)
		state := c.Query("state")
		if !validateStateToken(state) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state token"})
			return
		}

		// Exchange authorization code for access token
		code := c.Query("code")
		token, err := githubOauthConfig.Exchange(context.Background(), code)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange token"})
			return
		}

		// Get user info from GitHub
		client := githubOauthConfig.Client(context.Background(), token)
		resp, err := client.Get("https://api.github.com/user")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
			return
		}
		defer resp.Body.Close()

		data, _ := io.ReadAll(resp.Body)
		var githubUser GitHubUserInfo
		if err := json.Unmarshal(data, &githubUser); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse user info"})
			return
		}

		// Get user email if not public
		email := githubUser.Email
		if email == "" {
			email = getUserEmail(client)
		}

		// Create user object
		user := &User{
			ID:        fmt.Sprintf("github_%d", githubUser.ID),
			Email:     email,
			Name:      githubUser.Name,
			Provider:  "github",
			AvatarURL: githubUser.AvatarURL,
		}

		// Handle OAuth success with proper JWT middleware integration
		if err := handleOAuthSuccess(c, authMiddleware, user, "github"); err != nil {
			c.JSON(
				http.StatusInternalServerError,
				gin.H{"error": "Failed to complete authentication"},
			)
			return
		}
	}
}

// Helper functions
func generateStateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	oauthStateStore[state] = time.Now().Add(10 * time.Minute)
	return state
}

func validateStateToken(state string) bool {
	expiry, exists := oauthStateStore[state]
	if !exists {
		return false
	}
	if time.Now().After(expiry) {
		delete(oauthStateStore, state)
		return false
	}
	delete(oauthStateStore, state)
	return true
}

func cleanupExpiredStates() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		for state, expiry := range oauthStateStore {
			if now.After(expiry) {
				delete(oauthStateStore, state)
			}
		}
	}
}

func getUserEmail(client *http.Client) string {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var emails []struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}

	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &emails); err != nil {
		return ""
	}

	for _, email := range emails {
		if email.Primary {
			return email.Email
		}
	}

	if len(emails) > 0 {
		return emails[0].Email
	}

	return ""
}

func getStringFromClaims(claims gojwt.MapClaims, key string) string {
	if val, ok := claims[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// CORS middleware for development
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().
			Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// Route handlers
func indexHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "OAuth SSO Example with gin-jwt",
		"endpoints": gin.H{
			"demo_page":     "/demo",
			"google_login":  "/auth/google/login",
			"github_login":  "/auth/github/login",
			"profile":       "/api/profile (requires JWT)",
			"refresh_token": "/auth/refresh (requires JWT)",
			"logout":        "/api/logout (requires JWT)",
		},
	})
}

func profileHandler(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	user, _ := c.Get(identityKey)

	c.JSON(http.StatusOK, gin.H{
		"code": http.StatusOK,
		"user": user,
		"claims": gin.H{
			"id":       claims[identityKey],
			"email":    claims["email"],
			"name":     claims["name"],
			"provider": claims["provider"],
			"avatar":   claims["avatar"],
			"exp":      claims["exp"],
			"iat":      claims["iat"],
		},
	})
}

func handleNoRoute() func(c *gin.Context) {
	return func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"code":    "PAGE_NOT_FOUND",
			"message": "Page not found",
		})
	}
}
