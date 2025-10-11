package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/appleboy/gin-jwt/v2/core"
	"github.com/redis/rueidis"
)

// RedisRefreshTokenStore provides a Redis-based refresh token store with client-side caching
type RedisRefreshTokenStore struct {
	client rueidis.Client
	prefix string
	ctx    context.Context
}

// RedisConfig holds the configuration for Redis store
type RedisConfig struct {
	// Redis connection configuration
	Addr     string        // Redis server address (default: "localhost:6379")
	Password string        // Redis password (default: "")
	DB       int           // Redis database number (default: 0)

	// Client-side cache configuration
	CacheSize int           // Client-side cache size in bytes (default: 128MB)
	CacheTTL  time.Duration // Client-side cache TTL (default: 1 minute)

	// Connection pool configuration
	PoolSize        int           // Connection pool size (default: 10)
	ConnMaxIdleTime time.Duration // Max idle time for connections (default: 30 minutes)
	ConnMaxLifetime time.Duration // Max lifetime for connections (default: 1 hour)

	// Key prefix for Redis keys
	KeyPrefix string // Prefix for all Redis keys (default: "gin-jwt:")
}

// DefaultRedisConfig returns a default Redis configuration
func DefaultRedisConfig() *RedisConfig {
	return &RedisConfig{
		Addr:            "localhost:6379",
		Password:        "",
		DB:              0,
		CacheSize:       128 * 1024 * 1024, // 128MB
		CacheTTL:        time.Minute,
		PoolSize:        10,
		ConnMaxIdleTime: 30 * time.Minute,
		ConnMaxLifetime: time.Hour,
		KeyPrefix:       "gin-jwt:",
	}
}

// NewRedisRefreshTokenStore creates a new Redis-based refresh token store with client-side caching
func NewRedisRefreshTokenStore(config *RedisConfig) (*RedisRefreshTokenStore, error) {
	if config == nil {
		config = DefaultRedisConfig()
	}

	// Build Redis client options
	clientOpt := rueidis.ClientOption{
		InitAddress: []string{config.Addr},
		Password:    config.Password,
		SelectDB:    config.DB,

		// Connection configuration
		ConnWriteTimeout: 10 * time.Second,

		// Client-side cache configuration
		CacheSizeEachConn: config.CacheSize,
		DisableCache:      false,
	}

	// Create Redis client with client-side caching enabled
	client, err := rueidis.NewClient(clientOpt)
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis client: %w", err)
	}

	// Test connection
	ctx := context.Background()
	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisRefreshTokenStore{
		client: client,
		prefix: config.KeyPrefix,
		ctx:    ctx,
	}, nil
}

// Close closes the Redis client connection
func (s *RedisRefreshTokenStore) Close() error {
	s.client.Close()
	return nil
}

// buildKey creates a Redis key with the configured prefix
func (s *RedisRefreshTokenStore) buildKey(token string) string {
	return s.prefix + token
}

// Set stores a refresh token with associated user data and expiration
func (s *RedisRefreshTokenStore) Set(token string, userData interface{}, expiry time.Time) error {
	if token == "" {
		return errors.New("token cannot be empty")
	}

	tokenData := &core.RefreshTokenData{
		UserData: userData,
		Expiry:   expiry,
		Created:  time.Now(),
	}

	// Serialize token data to JSON
	data, err := json.Marshal(tokenData)
	if err != nil {
		return fmt.Errorf("failed to marshal token data: %w", err)
	}

	key := s.buildKey(token)
	ttl := time.Until(expiry)

	// If TTL is negative or zero, the token has already expired
	if ttl <= 0 {
		return errors.New("token expiry time must be in the future")
	}

	// Store in Redis with expiration
	cmd := s.client.B().Setex().Key(key).Seconds(int64(ttl.Seconds())).Value(string(data)).Build()
	if err := s.client.Do(s.ctx, cmd).Error(); err != nil {
		return fmt.Errorf("failed to store token in Redis: %w", err)
	}

	return nil
}

// Get retrieves user data associated with a refresh token
// This method benefits from client-side caching for frequently accessed tokens
func (s *RedisRefreshTokenStore) Get(token string) (interface{}, error) {
	if token == "" {
		return nil, core.ErrRefreshTokenNotFound
	}

	key := s.buildKey(token)

	// Use client-side cache by default
	cmd := s.client.B().Get().Key(key).Cache()
	result := s.client.DoCache(s.ctx, cmd, time.Minute)

	if result.Error() != nil {
		if rueidis.IsRedisNil(result.Error()) {
			return nil, core.ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("failed to get token from Redis: %w", result.Error())
	}

	data, err := result.ToString()
	if err != nil {
		return nil, fmt.Errorf("failed to convert Redis result to string: %w", err)
	}

	var tokenData core.RefreshTokenData
	if err := json.Unmarshal([]byte(data), &tokenData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token data: %w", err)
	}

	// Check if token has expired
	if tokenData.IsExpired() {
		// Clean up expired token asynchronously
		go func() {
			deleteCmd := s.client.B().Del().Key(key).Build()
			s.client.Do(context.Background(), deleteCmd)
		}()
		return nil, core.ErrRefreshTokenExpired
	}

	return tokenData.UserData, nil
}

// Delete removes a refresh token from storage
func (s *RedisRefreshTokenStore) Delete(token string) error {
	if token == "" {
		return nil // No error for empty token deletion
	}

	key := s.buildKey(token)
	cmd := s.client.B().Del().Key(key).Build()

	if err := s.client.Do(s.ctx, cmd).Error(); err != nil {
		return fmt.Errorf("failed to delete token from Redis: %w", err)
	}

	return nil
}

// Cleanup removes expired tokens and returns the number of tokens cleaned up
// Note: Redis automatically handles expiration, so this method scans for manually expired tokens
func (s *RedisRefreshTokenStore) Cleanup() (int, error) {
	pattern := s.buildKey("*")
	var cleaned int
	var cursor uint64

	for {
		// Scan for keys with our prefix
		cmd := s.client.B().Scan().Cursor(cursor).Match(pattern).Count(100).Build()
		result := s.client.Do(s.ctx, cmd)

		if result.Error() != nil {
			return cleaned, fmt.Errorf("failed to scan Redis keys: %w", result.Error())
		}

		scanResult, err := result.AsScanEntry()
		if err != nil {
			return cleaned, fmt.Errorf("failed to parse scan result: %w", err)
		}

		// Check each key for expiration
		for _, key := range scanResult.Elements {
			getCmd := s.client.B().Get().Key(key).Build()
			getResult := s.client.Do(s.ctx, getCmd)

			if rueidis.IsRedisNil(getResult.Error()) {
				// Key already expired/deleted
				continue
			}

			if getResult.Error() != nil {
				continue // Skip on error
			}

			data, err := getResult.ToString()
			if err != nil {
				continue // Skip on error
			}

			var tokenData core.RefreshTokenData
			if err := json.Unmarshal([]byte(data), &tokenData); err != nil {
				continue // Skip on error
			}

			if tokenData.IsExpired() {
				deleteCmd := s.client.B().Del().Key(key).Build()
				if s.client.Do(s.ctx, deleteCmd).Error() == nil {
					cleaned++
				}
			}
		}

		cursor = scanResult.Cursor
		if cursor == 0 {
			break
		}
	}

	return cleaned, nil
}

// Count returns the total number of active refresh tokens
func (s *RedisRefreshTokenStore) Count() (int, error) {
	pattern := s.buildKey("*")
	var count int
	var cursor uint64

	for {
		cmd := s.client.B().Scan().Cursor(cursor).Match(pattern).Count(100).Build()
		result := s.client.Do(s.ctx, cmd)

		if result.Error() != nil {
			return 0, fmt.Errorf("failed to scan Redis keys: %w", result.Error())
		}

		scanResult, err := result.AsScanEntry()
		if err != nil {
			return 0, fmt.Errorf("failed to parse scan result: %w", err)
		}

		count += len(scanResult.Elements)
		cursor = scanResult.Cursor

		if cursor == 0 {
			break
		}
	}

	return count, nil
}

// Ping tests the Redis connection
func (s *RedisRefreshTokenStore) Ping() error {
	return s.client.Do(s.ctx, s.client.B().Ping().Build()).Error()
}

// FlushDB removes all keys from the current Redis database (useful for testing)
// Note: This method is not part of the RefreshTokenStorer interface
func (s *RedisRefreshTokenStore) FlushDB() error {
	return s.client.Do(s.ctx, s.client.B().Flushdb().Build()).Error()
}