package jwt

import (
	"testing"
	"time"

	"github.com/appleboy/gin-jwt/v2/store"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestGinJWTMiddleware_ConvenienceMethodsOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)

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
		assert.Equal(t, "localhost:6379", middleware.RedisConfig.Addr, "should set default address")
	})

	t.Run("EnableRedisStoreWithAddr", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		testAddr := "redis.example.com:6379"

		// Test EnableRedisStoreWithAddr
		result := middleware.EnableRedisStoreWithAddr(testAddr)
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, testAddr, middleware.RedisConfig.Addr, "should set custom address")
	})

	t.Run("EnableRedisStoreWithOptions", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		testAddr := "redis.example.com:6379"
		testPassword := "testpass"
		testDB := 5

		// Test EnableRedisStoreWithOptions
		result := middleware.EnableRedisStoreWithOptions(testAddr, testPassword, testDB)
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, testAddr, middleware.RedisConfig.Addr, "should set custom address")
		assert.Equal(t, testPassword, middleware.RedisConfig.Password, "should set custom password")
		assert.Equal(t, testDB, middleware.RedisConfig.DB, "should set custom DB")
	})

	t.Run("EnableRedisStoreWithConfig", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		customConfig := &store.RedisConfig{
			Addr:      "custom.redis.com:6379",
			Password:  "custom-password",
			DB:        3,
			CacheSize: 256 * 1024 * 1024, // 256MB
			CacheTTL:  5 * time.Minute,
			KeyPrefix: "custom-prefix:",
		}

		// Test EnableRedisStoreWithConfig
		result := middleware.EnableRedisStoreWithConfig(customConfig)
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, customConfig, middleware.RedisConfig, "should use custom config")
	})

	t.Run("SetRedisClientSideCache", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		// Test SetRedisClientSideCache with no existing config
		cacheSize := 64 * 1024 * 1024 // 64MB
		cacheTTL := 30 * time.Second
		result := middleware.SetRedisClientSideCache(cacheSize, cacheTTL)
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.NotNil(t, middleware.RedisConfig, "should create default config if none exists")
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

		testAddr := "chain.redis.com:6379"
		cacheSize := 32 * 1024 * 1024 // 32MB
		cacheTTL := 15 * time.Second

		// Test chained configuration
		result := middleware.
			EnableRedisStoreWithAddr(testAddr).
			SetRedisClientSideCache(cacheSize, cacheTTL)

		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, testAddr, middleware.RedisConfig.Addr, "should set address")
		assert.Equal(t, cacheSize, middleware.RedisConfig.CacheSize, "should set cache size")
		assert.Equal(t, cacheTTL, middleware.RedisConfig.CacheTTL, "should set cache TTL")
		assert.Equal(t, "gin-jwt:", middleware.RedisConfig.KeyPrefix, "should have default key prefix")
	})

	t.Run("MethodsWithExistingConfig", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
			RedisConfig: &store.RedisConfig{
				Addr:      "existing.redis.com:6379",
				Password:  "existing-pass",
				DB:        1,
				KeyPrefix: "existing:",
			},
		}

		// Test SetRedisClientSideCache with existing config
		cacheSize := 128 * 1024 * 1024 // 128MB
		cacheTTL := 2 * time.Minute
		result := middleware.SetRedisClientSideCache(cacheSize, cacheTTL)

		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.Equal(t, cacheSize, middleware.RedisConfig.CacheSize, "should update cache size")
		assert.Equal(t, cacheTTL, middleware.RedisConfig.CacheTTL, "should update cache TTL")
		// Should preserve existing settings
		assert.Equal(t, "existing.redis.com:6379", middleware.RedisConfig.Addr, "should preserve existing address")
		assert.Equal(t, "existing-pass", middleware.RedisConfig.Password, "should preserve existing password")
		assert.Equal(t, 1, middleware.RedisConfig.DB, "should preserve existing DB")
		assert.Equal(t, "existing:", middleware.RedisConfig.KeyPrefix, "should preserve existing prefix")
	})

	t.Run("DefaultConfiguration", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		// Test EnableRedisStore with defaults
		result := middleware.EnableRedisStore()
		config := result.RedisConfig

		// Verify all default values
		assert.Equal(t, "localhost:6379", config.Addr, "should have default address")
		assert.Equal(t, "", config.Password, "should have empty default password")
		assert.Equal(t, 0, config.DB, "should have default DB")
		assert.Equal(t, 128*1024*1024, config.CacheSize, "should have default cache size")
		assert.Equal(t, time.Minute, config.CacheTTL, "should have default cache TTL")
		assert.Equal(t, "gin-jwt:", config.KeyPrefix, "should have default key prefix")
	})
}