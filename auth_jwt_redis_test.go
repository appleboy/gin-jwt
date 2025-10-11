package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/appleboy/gin-jwt/v2/store"
	"github.com/gin-gonic/gin"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/redis"
)

func setupRedisContainerForJWT(t *testing.T) (*redis.RedisContainer, string, string) {
	ctx := context.Background()

	// Start Redis container
	redisContainer, err := redis.Run(ctx,
		"redis:alpine",
	)
	require.NoError(t, err, "failed to start Redis container")

	// Get host and port
	host, err := redisContainer.Host(ctx)
	require.NoError(t, err, "failed to get Redis host")

	mappedPort, err := redisContainer.MappedPort(ctx, "6379")
	require.NoError(t, err, "failed to get Redis port")

	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(redisContainer); err != nil {
			t.Logf("failed to terminate Redis container: %s", err)
		}
	})

	return redisContainer, host, mappedPort.Port()
}

func TestGinJWTMiddleware_RedisStore_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	_, host, port := setupRedisContainerForJWT(t)

	// Create middleware with Redis store
	middleware := createTestMiddleware(t, fmt.Sprintf("%s:%s", host, port))

	// Initialize middleware
	err := middleware.MiddlewareInit()
	require.NoError(t, err, "middleware initialization should not fail")

	// Create test router
	r := gin.New()
	r.POST("/login", middleware.LoginHandler)
	r.POST("/refresh", middleware.RefreshHandler)

	auth := r.Group("/auth")
	auth.Use(middleware.MiddlewareFunc())
	{
		auth.GET("/hello", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "hello"})
		})
	}

	t.Run("LoginAndRefreshWithRedis", func(t *testing.T) {
		testLoginAndRefreshFlow(t, r, middleware)
	})

	t.Run("TokenPersistenceAcrossRequests", func(t *testing.T) {
		testTokenPersistenceAcrossRequests(t, r, middleware)
	})

	t.Run("RedisStoreOperations", func(t *testing.T) {
		testRedisStoreOperations(t, middleware)
	})
}

func TestGinJWTMiddleware_RedisStoreFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create middleware with invalid Redis configuration (should fallback to memory)
	middleware := &GinJWTMiddleware{
		Realm:         "test zone",
		Key:           []byte("secret key"),
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		IdentityKey:   "id",
		Authenticator: testAuthenticator,
		PayloadFunc:   testPayloadFunc,
		// Enable Redis with invalid config to test fallback
		UseRedisStore: true,
		RedisConfig: &store.RedisConfig{
			Addr: "invalid-host:6379", // This should fail
		},
	}

	// Initialize middleware (should fallback to memory store)
	err := middleware.MiddlewareInit()
	require.NoError(t, err, "middleware initialization should not fail even with invalid Redis")

	// Verify that it fell back to in-memory store
	assert.NotNil(t, middleware.inMemoryStore, "should have created in-memory store as fallback")
	assert.Equal(t, middleware.RefreshTokenStore, middleware.inMemoryStore, "should use in-memory store as fallback")
}

func TestGinJWTMiddleware_ConvenienceMethods(t *testing.T) {
	gin.SetMode(gin.TestMode)

	_, host, port := setupRedisContainerForJWT(t)

	redisAddr := fmt.Sprintf("%s:%s", host, port)

	t.Run("EnableRedisStore", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		// Test EnableRedisStore
		result := middleware.EnableRedisStore()
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.NotNil(t, middleware.RedisConfig, "should set default Redis config")
	})

	t.Run("EnableRedisStoreWithAddr", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		// Test EnableRedisStoreWithAddr
		result := middleware.EnableRedisStoreWithAddr(redisAddr)
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, redisAddr, middleware.RedisConfig.Addr, "should set custom address")
	})

	t.Run("EnableRedisStoreWithOptions", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		// Test EnableRedisStoreWithOptions
		result := middleware.EnableRedisStoreWithOptions(redisAddr, "testpass", 1)
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, redisAddr, middleware.RedisConfig.Addr, "should set custom address")
		assert.Equal(t, "testpass", middleware.RedisConfig.Password, "should set custom password")
		assert.Equal(t, 1, middleware.RedisConfig.DB, "should set custom DB")
	})

	t.Run("SetRedisClientSideCache", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		// Test SetRedisClientSideCache
		cacheSize := 64 * 1024 * 1024 // 64MB
		cacheTTL := 30 * time.Second
		result := middleware.SetRedisClientSideCache(cacheSize, cacheTTL)
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.Equal(t, cacheSize, middleware.RedisConfig.CacheSize, "should set cache size")
		assert.Equal(t, cacheTTL, middleware.RedisConfig.CacheTTL, "should set cache TTL")
	})

	t.Run("ChainedConfiguration", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:         "test zone",
			Key:           []byte("secret key"),
			Timeout:       time.Hour,
			MaxRefresh:    time.Hour * 24,
			IdentityKey:   "id",
			Authenticator: testAuthenticator,
			PayloadFunc:   testPayloadFunc,
		}

		// Test chained configuration
		result := middleware.
			EnableRedisStoreWithAddr(redisAddr).
			SetRedisClientSideCache(32*1024*1024, 15*time.Second)

		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, redisAddr, middleware.RedisConfig.Addr, "should set address")
		assert.Equal(t, 32*1024*1024, middleware.RedisConfig.CacheSize, "should set cache size")
		assert.Equal(t, 15*time.Second, middleware.RedisConfig.CacheTTL, "should set cache TTL")

		// Test that it actually works
		err := middleware.MiddlewareInit()
		assert.NoError(t, err, "chained configuration should initialize successfully")
	})
}

func createTestMiddleware(t *testing.T, redisAddr string) *GinJWTMiddleware {
	return &GinJWTMiddleware{
		Realm:         "test zone",
		Key:           []byte("secret key"),
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		IdentityKey:   "id",
		Authenticator: testAuthenticator,
		PayloadFunc:   testPayloadFunc,
		UseRedisStore: true,
		RedisConfig: &store.RedisConfig{
			Addr:      redisAddr,
			Password:  "",
			DB:        0,
			CacheSize: 1024 * 1024, // 1MB for testing
			KeyPrefix: "test-jwt:",
		},
	}
}

func testAuthenticator(c *gin.Context) (interface{}, error) {
	var loginVals struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBind(&loginVals); err != nil {
		return "", ErrMissingLoginValues
	}

	if loginVals.Username == "admin" && loginVals.Password == "admin" {
		return map[string]interface{}{
			"username": "admin",
			"userid":   1,
		}, nil
	}

	return nil, ErrFailedAuthentication
}

func testPayloadFunc(data interface{}) gojwt.MapClaims {
	if v, ok := data.(map[string]interface{}); ok {
		return gojwt.MapClaims{
			"id":       v["userid"],
			"username": v["username"],
		}
	}
	return gojwt.MapClaims{}
}

func testLoginAndRefreshFlow(t *testing.T, r *gin.Engine, middleware *GinJWTMiddleware) {
	// Test login
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", strings.NewReader(`{"username":"admin","password":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code, "login should succeed")
	assert.Contains(t, w.Body.String(), "access_token", "response should contain access token")
	assert.Contains(t, w.Body.String(), "refresh_token", "response should contain refresh token")

	// Extract tokens from response
	var loginResp map[string]interface{}
	err := parseJSON(w.Body.String(), &loginResp)
	require.NoError(t, err, "should be able to parse login response")

	accessToken := loginResp["access_token"].(string)
	refreshToken := loginResp["refresh_token"].(string)

	// Test protected endpoint with access token
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code, "protected endpoint should be accessible with valid token")

	// Test refresh token
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/refresh", strings.NewReader(fmt.Sprintf(`{"refresh_token":"%s"}`, refreshToken)))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code, "refresh should succeed")
	assert.Contains(t, w.Body.String(), "access_token", "refresh response should contain new access token")
	assert.Contains(t, w.Body.String(), "refresh_token", "refresh response should contain new refresh token")
}

func testTokenPersistenceAcrossRequests(t *testing.T, r *gin.Engine, middleware *GinJWTMiddleware) {
	// Login and get refresh token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", strings.NewReader(`{"username":"admin","password":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	var loginResp map[string]interface{}
	err := parseJSON(w.Body.String(), &loginResp)
	require.NoError(t, err)

	refreshToken := loginResp["refresh_token"].(string)

	// Simulate some time passing and multiple refresh requests
	for i := 0; i < 3; i++ {
		time.Sleep(10 * time.Millisecond) // Small delay to simulate real usage

		w = httptest.NewRecorder()
		req, _ = http.NewRequest("POST", "/refresh", strings.NewReader(fmt.Sprintf(`{"refresh_token":"%s"}`, refreshToken)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code, fmt.Sprintf("refresh %d should succeed", i+1))

		// Update refresh token for next iteration
		var refreshResp map[string]interface{}
		err := parseJSON(w.Body.String(), &refreshResp)
		require.NoError(t, err, fmt.Sprintf("should parse refresh response %d", i+1))
		refreshToken = refreshResp["refresh_token"].(string)
	}
}

func testRedisStoreOperations(t *testing.T, middleware *GinJWTMiddleware) {
	// Verify that Redis store is being used
	redisStore, ok := middleware.RefreshTokenStore.(*store.RedisRefreshTokenStore)
	require.True(t, ok, "should be using Redis store")

	// Test store operations directly
	testToken := "direct-test-token"
	testData := map[string]interface{}{"test": "data"}
	expiry := time.Now().Add(time.Hour)

	// Test Set
	err := redisStore.Set(testToken, testData, expiry)
	assert.NoError(t, err, "direct set should succeed")

	// Test Get
	retrievedData, err := redisStore.Get(testToken)
	assert.NoError(t, err, "direct get should succeed")
	assert.Equal(t, testData, retrievedData, "retrieved data should match")

	// Test Count
	count, err := redisStore.Count()
	assert.NoError(t, err, "count should succeed")
	assert.GreaterOrEqual(t, count, 1, "count should include our test token")

	// Test Delete
	err = redisStore.Delete(testToken)
	assert.NoError(t, err, "direct delete should succeed")

	// Verify deletion
	_, err = redisStore.Get(testToken)
	assert.Error(t, err, "token should not exist after deletion")
}

// Helper function to parse JSON response
func parseJSON(jsonStr string, v interface{}) error {
	return json.Unmarshal([]byte(jsonStr), v)
}