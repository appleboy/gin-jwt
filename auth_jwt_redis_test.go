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

	"github.com/appleboy/gin-jwt/v3/store"
	"github.com/gin-gonic/gin"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/redis"
)

func setupRedisContainerForJWT(t *testing.T) (*redis.RedisContainer, string, string) {
	ctx := context.Background()
	t.Helper()

	// Start Redis container
	redisContainer, err := redis.Run(ctx, "redis:8-alpine")
	require.NoError(t, err, "failed to start Redis container")

	// Get host and port
	host, err := redisContainer.Host(ctx)
	require.NoError(t, err, "failed to get Redis host")

	mappedPort, err := redisContainer.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err, "failed to get Redis port")

	t.Cleanup(func() {
		if err := redisContainer.Terminate(ctx); err != nil {
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
		testLoginAndRefreshFlow(t, r)
	})

	t.Run("TokenPersistenceAcrossRequests", func(t *testing.T) {
		testTokenPersistenceAcrossRequests(t, r)
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

func TestGinJWTMiddleware_FunctionalOptions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	_, host, port := setupRedisContainerForJWT(t)

	redisAddr := fmt.Sprintf("%s:%s", host, port)

	t.Run("EnableRedisStoreDefault", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		// Test EnableRedisStore with no options (default)
		result := middleware.EnableRedisStore()
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.NotNil(t, middleware.RedisConfig, "should set default Redis config")
		assert.Equal(t, "localhost:6379", middleware.RedisConfig.Addr, "should use default address")
	})

	t.Run("EnableRedisStoreWithAddr", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		// Test EnableRedisStore with address option
		result := middleware.EnableRedisStore(WithRedisAddr(redisAddr))
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, redisAddr, middleware.RedisConfig.Addr, "should set custom address")
	})

	t.Run("EnableRedisStoreWithAuth", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		// Test EnableRedisStore with auth options
		result := middleware.EnableRedisStore(
			WithRedisAddr(redisAddr),
			WithRedisAuth("testpass", 1),
		)
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, redisAddr, middleware.RedisConfig.Addr, "should set custom address")
		assert.Equal(t, "testpass", middleware.RedisConfig.Password, "should set custom password")
		assert.Equal(t, 1, middleware.RedisConfig.DB, "should set custom DB")
	})

	t.Run("EnableRedisStoreWithCache", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		// Test EnableRedisStore with cache options
		cacheSize := 64 * 1024 * 1024 // 64MB
		cacheTTL := 30 * time.Second
		result := middleware.EnableRedisStore(
			WithRedisAddr(redisAddr),
			WithRedisCache(cacheSize, cacheTTL),
		)
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, redisAddr, middleware.RedisConfig.Addr, "should set address")
		assert.Equal(t, cacheSize, middleware.RedisConfig.CacheSize, "should set cache size")
		assert.Equal(t, cacheTTL, middleware.RedisConfig.CacheTTL, "should set cache TTL")
	})

	t.Run("EnableRedisStoreWithPool", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		// Test EnableRedisStore with pool options
		poolSize := 20
		maxIdleTime := time.Hour
		maxLifetime := 2 * time.Hour
		result := middleware.EnableRedisStore(
			WithRedisAddr(redisAddr),
			WithRedisPool(poolSize, maxIdleTime, maxLifetime),
		)
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, poolSize, middleware.RedisConfig.PoolSize, "should set pool size")
		assert.Equal(t, maxIdleTime, middleware.RedisConfig.ConnMaxIdleTime, "should set max idle time")
		assert.Equal(t, maxLifetime, middleware.RedisConfig.ConnMaxLifetime, "should set max lifetime")
	})

	t.Run("EnableRedisStoreWithKeyPrefix", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		// Test EnableRedisStore with key prefix option
		keyPrefix := "test-jwt:"
		result := middleware.EnableRedisStore(
			WithRedisAddr(redisAddr),
			WithRedisKeyPrefix(keyPrefix),
		)
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, keyPrefix, middleware.RedisConfig.KeyPrefix, "should set key prefix")
	})

	t.Run("EnableRedisStoreWithAllOptions", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:         "test zone",
			Key:           []byte("secret key"),
			Timeout:       time.Hour,
			MaxRefresh:    time.Hour * 24,
			IdentityKey:   "id",
			Authenticator: testAuthenticator,
			PayloadFunc:   testPayloadFunc,
		}

		// Test EnableRedisStore with all options
		result := middleware.EnableRedisStore(
			WithRedisAddr(redisAddr),
			WithRedisAuth("testpass", 1),
			WithRedisCache(32*1024*1024, 15*time.Second),
			WithRedisPool(25, 2*time.Hour, 4*time.Hour),
			WithRedisKeyPrefix("test-app:"),
		)

		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, redisAddr, middleware.RedisConfig.Addr, "should set address")
		assert.Equal(t, "testpass", middleware.RedisConfig.Password, "should set password")
		assert.Equal(t, 1, middleware.RedisConfig.DB, "should set DB")
		assert.Equal(t, 32*1024*1024, middleware.RedisConfig.CacheSize, "should set cache size")
		assert.Equal(t, 15*time.Second, middleware.RedisConfig.CacheTTL, "should set cache TTL")
		assert.Equal(t, 25, middleware.RedisConfig.PoolSize, "should set pool size")
		assert.Equal(t, 2*time.Hour, middleware.RedisConfig.ConnMaxIdleTime, "should set max idle time")
		assert.Equal(t, 4*time.Hour, middleware.RedisConfig.ConnMaxLifetime, "should set max lifetime")
		assert.Equal(t, "test-app:", middleware.RedisConfig.KeyPrefix, "should set key prefix")

		// Test that it actually works (but use working address for actual initialization)
		middleware.EnableRedisStore(WithRedisAddr(redisAddr)) // Reset to working address
		err := middleware.MiddlewareInit()
		assert.NoError(t, err, "configuration with all options should initialize successfully")
	})
}

func createTestMiddleware(t *testing.T, redisAddr string) *GinJWTMiddleware {
	middleware := &GinJWTMiddleware{
		Realm:         "test zone",
		Key:           []byte("secret key"),
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		IdentityKey:   "id",
		Authenticator: testAuthenticator,
		PayloadFunc:   testPayloadFunc,
	}

	// Configure Redis using functional options
	middleware.EnableRedisStore(
		WithRedisAddr(redisAddr),
		WithRedisCache(1024*1024, 50*time.Millisecond), // 1MB for testing, very short TTL for testing
		WithRedisKeyPrefix("test-jwt:"),
	)

	return middleware
}

func testAuthenticator(c *gin.Context) (any, error) {
	var loginVals struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBind(&loginVals); err != nil {
		return "", ErrMissingLoginValues
	}

	if loginVals.Username == "admin" && loginVals.Password == "admin" {
		return map[string]any{
			"username": "admin",
			"userid":   1,
		}, nil
	}

	return nil, ErrFailedAuthentication
}

func testPayloadFunc(data any) gojwt.MapClaims {
	if v, ok := data.(map[string]any); ok {
		return gojwt.MapClaims{
			"id":       v["userid"],
			"username": v["username"],
		}
	}
	return gojwt.MapClaims{}
}

func testLoginAndRefreshFlow(t *testing.T, r *gin.Engine) {
	// Test login
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", strings.NewReader(`{"username":"admin","password":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code, "login should succeed")
	assert.Contains(t, w.Body.String(), "access_token", "response should contain access token")
	assert.Contains(t, w.Body.String(), "refresh_token", "response should contain refresh token")

	// Extract tokens from response
	var loginResp map[string]any
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

func testTokenPersistenceAcrossRequests(t *testing.T, r *gin.Engine) {
	// Login and get refresh token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", strings.NewReader(`{"username":"admin","password":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	var loginResp map[string]any
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
		var refreshResp map[string]any
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
	ctx := context.Background()
	testToken := "direct-test-token"
	testData := map[string]any{"test": "data"}
	expiry := time.Now().Add(time.Hour)

	// Test Set
	err := redisStore.Set(ctx, testToken, testData, expiry)
	assert.NoError(t, err, "direct set should succeed")

	// Test Get
	retrievedData, err := redisStore.Get(ctx, testToken)
	assert.NoError(t, err, "direct get should succeed")
	assert.Equal(t, testData, retrievedData, "retrieved data should match")

	// Test Count
	count, err := redisStore.Count(ctx)
	assert.NoError(t, err, "count should succeed")
	assert.GreaterOrEqual(t, count, 1, "count should include our test token")

	// Test Delete
	err = redisStore.Delete(ctx, testToken)
	assert.NoError(t, err, "direct delete should succeed")

	// Verify deletion - wait for cache TTL to expire
	time.Sleep(100 * time.Millisecond)

	// The Get method should return an error for deleted tokens
	_, err = redisStore.Get(ctx, testToken)
	assert.Error(t, err, "token should not exist after deletion")
}

// Helper function to parse JSON response
func parseJSON(jsonStr string, v any) error {
	return json.Unmarshal([]byte(jsonStr), v)
}
