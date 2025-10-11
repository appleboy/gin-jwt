package jwt

import (
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestGinJWTMiddleware_FunctionalOptionsOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)

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
		assert.Equal(t, "localhost:6379", middleware.RedisConfig.Addr, "should set default address")
	})

	t.Run("EnableRedisStoreWithSingleOption", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		testAddr := "redis.example.com:6379"

		// Test EnableRedisStore with single option
		result := middleware.EnableRedisStore(WithRedisAddr(testAddr))
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, testAddr, middleware.RedisConfig.Addr, "should set custom address")
		// Should still have defaults for other values
		assert.Equal(t, "", middleware.RedisConfig.Password, "should have default empty password")
		assert.Equal(t, 0, middleware.RedisConfig.DB, "should have default DB")
	})

	t.Run("EnableRedisStoreWithMultipleOptions", func(t *testing.T) {
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

		// Test EnableRedisStore with multiple options
		result := middleware.EnableRedisStore(
			WithRedisAddr(testAddr),
			WithRedisAuth(testPassword, testDB),
		)
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, testAddr, middleware.RedisConfig.Addr, "should set custom address")
		assert.Equal(t, testPassword, middleware.RedisConfig.Password, "should set custom password")
		assert.Equal(t, testDB, middleware.RedisConfig.DB, "should set custom DB")
	})

	t.Run("EnableRedisStoreWithCacheOptions", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		cacheSize := 64 * 1024 * 1024 // 64MB
		cacheTTL := 30 * time.Second

		// Test EnableRedisStore with cache options
		result := middleware.EnableRedisStore(
			WithRedisCache(cacheSize, cacheTTL),
		)
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.NotNil(t, middleware.RedisConfig, "should create Redis config")
		assert.Equal(t, cacheSize, middleware.RedisConfig.CacheSize, "should set cache size")
		assert.Equal(t, cacheTTL, middleware.RedisConfig.CacheTTL, "should set cache TTL")
	})

	t.Run("EnableRedisStoreWithPoolOptions", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		poolSize := 20
		maxIdleTime := 2 * time.Hour
		maxLifetime := 4 * time.Hour

		// Test EnableRedisStore with pool options
		result := middleware.EnableRedisStore(
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

		keyPrefix := "test-app:"

		// Test EnableRedisStore with key prefix
		result := middleware.EnableRedisStore(
			WithRedisKeyPrefix(keyPrefix),
		)
		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, keyPrefix, middleware.RedisConfig.KeyPrefix, "should set key prefix")
	})

	t.Run("EnableRedisStoreWithAllOptions", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		testAddr := "custom.redis.com:6379"
		testPassword := "custom-password"
		testDB := 3
		cacheSize := 256 * 1024 * 1024 // 256MB
		cacheTTL := 5 * time.Minute
		poolSize := 25
		maxIdleTime := 3 * time.Hour
		maxLifetime := 6 * time.Hour
		keyPrefix := "custom-prefix:"

		// Test EnableRedisStore with all options
		result := middleware.EnableRedisStore(
			WithRedisAddr(testAddr),
			WithRedisAuth(testPassword, testDB),
			WithRedisCache(cacheSize, cacheTTL),
			WithRedisPool(poolSize, maxIdleTime, maxLifetime),
			WithRedisKeyPrefix(keyPrefix),
		)

		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, testAddr, middleware.RedisConfig.Addr, "should set address")
		assert.Equal(t, testPassword, middleware.RedisConfig.Password, "should set password")
		assert.Equal(t, testDB, middleware.RedisConfig.DB, "should set DB")
		assert.Equal(t, cacheSize, middleware.RedisConfig.CacheSize, "should set cache size")
		assert.Equal(t, cacheTTL, middleware.RedisConfig.CacheTTL, "should set cache TTL")
		assert.Equal(t, poolSize, middleware.RedisConfig.PoolSize, "should set pool size")
		assert.Equal(t, maxIdleTime, middleware.RedisConfig.ConnMaxIdleTime, "should set max idle time")
		assert.Equal(t, maxLifetime, middleware.RedisConfig.ConnMaxLifetime, "should set max lifetime")
		assert.Equal(t, keyPrefix, middleware.RedisConfig.KeyPrefix, "should set key prefix")
	})

	t.Run("MultipleEnableRedisStoreCalls", func(t *testing.T) {
		middleware := &GinJWTMiddleware{
			Realm:       "test zone",
			Key:         []byte("secret key"),
			Timeout:     time.Hour,
			MaxRefresh:  time.Hour * 24,
			IdentityKey: "id",
		}

		// First call
		middleware.EnableRedisStore(
			WithRedisAddr("first.redis.com:6379"),
			WithRedisAuth("first-pass", 1),
		)

		// Second call should override the first
		result := middleware.EnableRedisStore(
			WithRedisAddr("second.redis.com:6379"),
			WithRedisAuth("second-pass", 2),
			WithRedisKeyPrefix("second:"),
		)

		assert.Equal(t, middleware, result, "should return self for chaining")
		assert.True(t, middleware.UseRedisStore, "should enable Redis store")
		assert.Equal(t, "second.redis.com:6379", middleware.RedisConfig.Addr, "should use second address")
		assert.Equal(t, "second-pass", middleware.RedisConfig.Password, "should use second password")
		assert.Equal(t, 2, middleware.RedisConfig.DB, "should use second DB")
		assert.Equal(t, "second:", middleware.RedisConfig.KeyPrefix, "should use second key prefix")
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
		assert.Equal(t, 10, config.PoolSize, "should have default pool size")
		assert.Equal(t, 30*time.Minute, config.ConnMaxIdleTime, "should have default max idle time")
		assert.Equal(t, time.Hour, config.ConnMaxLifetime, "should have default max lifetime")
		assert.Equal(t, "gin-jwt:", config.KeyPrefix, "should have default key prefix")
	})
}