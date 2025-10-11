package store

import (
	"fmt"

	"github.com/appleboy/gin-jwt/v3/core"
)

// StoreType represents the type of store to create
type StoreType string

const (
	// MemoryStore represents an in-memory token store
	MemoryStore StoreType = "memory"
	// RedisStore represents a Redis-based token store
	RedisStore StoreType = "redis"
)

// Config holds the configuration for creating a token store
type Config struct {
	Type  StoreType    // Type of store to create (memory or redis)
	Redis *RedisConfig // Redis configuration (only used when Type is RedisStore)
}

// DefaultConfig returns a default configuration with memory store
func DefaultConfig() *Config {
	return &Config{
		Type:  MemoryStore,
		Redis: nil,
	}
}

// NewMemoryConfig creates a configuration for memory store
func NewMemoryConfig() *Config {
	return &Config{
		Type:  MemoryStore,
		Redis: nil,
	}
}

// NewRedisConfig creates a configuration for Redis store
func NewRedisConfig(redisConfig *RedisConfig) *Config {
	if redisConfig == nil {
		redisConfig = DefaultRedisConfig()
	}
	return &Config{
		Type:  RedisStore,
		Redis: redisConfig,
	}
}

// Factory provides methods to create different types of token stores
type Factory struct{}

// NewFactory creates a new store factory
func NewFactory() *Factory {
	return &Factory{}
}

// CreateStore creates a token store based on the provided configuration
func (f *Factory) CreateStore(config *Config) (core.TokenStore, error) {
	if config == nil {
		config = DefaultConfig()
	}

	switch config.Type {
	case MemoryStore:
		return NewInMemoryRefreshTokenStore(), nil

	case RedisStore:
		redisConfig := config.Redis
		if redisConfig == nil {
			redisConfig = DefaultRedisConfig()
		}
		return NewRedisRefreshTokenStore(redisConfig)

	default:
		return nil, fmt.Errorf("unsupported store type: %s", config.Type)
	}
}

// Convenience functions for creating stores

// NewStore creates a token store with the given configuration
func NewStore(config *Config) (core.TokenStore, error) {
	factory := NewFactory()
	return factory.CreateStore(config)
}

// NewMemoryStore creates a new in-memory token store
func NewMemoryStore() core.TokenStore {
	return NewInMemoryRefreshTokenStore()
}

// NewRedisStore creates a new Redis token store with the given configuration
func NewRedisStore(config *RedisConfig) (core.TokenStore, error) {
	return NewRedisRefreshTokenStore(config)
}

// MustNewStore creates a token store with the given configuration and panics on error
func MustNewStore(config *Config) core.TokenStore {
	store, err := NewStore(config)
	if err != nil {
		panic(fmt.Sprintf("failed to create token store: %v", err))
	}
	return store
}

// MustNewMemoryStore creates a new in-memory token store (never fails)
func MustNewMemoryStore() core.TokenStore {
	return NewMemoryStore()
}

// MustNewRedisStore creates a new Redis token store and panics on error
func MustNewRedisStore(config *RedisConfig) core.TokenStore {
	store, err := NewRedisStore(config)
	if err != nil {
		panic(fmt.Sprintf("failed to create Redis token store: %v", err))
	}
	return store
}