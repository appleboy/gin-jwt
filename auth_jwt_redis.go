package jwt

import (
	"crypto/tls"
	"log"
	"time"

	"github.com/appleboy/gin-jwt/v3/store"
)

// RedisOption defines a function type for configuring Redis store
type RedisOption func(*store.RedisConfig)

// WithRedisAddr sets the Redis server address
func WithRedisAddr(addr string) RedisOption {
	return func(config *store.RedisConfig) {
		config.Addr = addr
	}
}

// WithRedisAuth sets Redis authentication
func WithRedisAuth(password string, db int) RedisOption {
	return func(config *store.RedisConfig) {
		config.Password = password
		config.DB = db
	}
}

// WithRedisCache configures client-side cache
func WithRedisCache(size int, ttl time.Duration) RedisOption {
	return func(config *store.RedisConfig) {
		config.CacheSize = size
		config.CacheTTL = ttl
	}
}

// WithRedisPool configures connection pool
func WithRedisPool(poolSize int, maxIdleTime, maxLifetime time.Duration) RedisOption {
	return func(config *store.RedisConfig) {
		config.PoolSize = poolSize
		config.ConnMaxIdleTime = maxIdleTime
		config.ConnMaxLifetime = maxLifetime
	}
}

// WithRedisKeyPrefix sets the key prefix
func WithRedisKeyPrefix(prefix string) RedisOption {
	return func(config *store.RedisConfig) {
		config.KeyPrefix = prefix
	}
}

// WithRedisTLS sets the TLS configuration for secure connections
func WithRedisTLS(tlsConfig *tls.Config) RedisOption {
	return func(config *store.RedisConfig) {
		config.TLSConfig = tlsConfig
	}
}

// EnableRedisStore enables Redis store with optional configuration
func (mw *GinJWTMiddleware) EnableRedisStore(opts ...RedisOption) *GinJWTMiddleware {
	mw.UseRedisStore = true

	// Start with default config
	config := store.DefaultRedisConfig()

	// Apply all options
	for _, opt := range opts {
		opt(config)
	}

	mw.RedisConfig = config
	return mw
}

// initializeRedisStore attempts to create and initialize Redis store
// Falls back to in-memory store if Redis connection fails
func (mw *GinJWTMiddleware) initializeRedisStore() {
	if mw.UseRedisStore {
		// Try to create Redis store
		redisConfig := mw.RedisConfig
		if redisConfig == nil {
			redisConfig = store.DefaultRedisConfig()
		}

		redisStore, err := store.NewRedisRefreshTokenStore(redisConfig)
		if err != nil {
			// Fallback to in-memory store
			log.Printf("Failed to connect to Redis: %v, falling back to in-memory store", err)
			mw.RefreshTokenStore = mw.inMemoryStore
		} else {
			log.Println("Successfully connected to Redis store with client-side cache enabled")
			mw.RefreshTokenStore = redisStore
		}
	}
}
