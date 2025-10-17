package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/appleboy/gin-jwt/v3/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/redis"
)

func setupRedisContainer(t *testing.T) (*redis.RedisContainer, string, string) {
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

func TestRedisRefreshTokenStore_Integration(t *testing.T) {
	_, host, port := setupRedisContainer(t)

	// Create Redis store configuration
	config := &RedisConfig{
		Addr:      fmt.Sprintf("%s:%s", host, port),
		Password:  "",
		DB:        0,
		CacheSize: 1024 * 1024, // 1MB for testing
		CacheTTL:  time.Second,
		KeyPrefix: "test-jwt:",
	}

	store, err := NewRedisRefreshTokenStore(config)
	require.NoError(t, err, "failed to create Redis store")
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Logf("failed to close Redis store: %v", closeErr)
		}
	}()

	t.Run("BasicOperations", func(t *testing.T) {
		testBasicOperations(t, store)
	})

	t.Run("Expiration", func(t *testing.T) {
		testExpiration(t, store)
	})

	t.Run("Cleanup", func(t *testing.T) {
		testCleanup(t, store)
	})

	t.Run("Count", func(t *testing.T) {
		testCount(t, store)
	})

	t.Run("ClientSideCache", func(t *testing.T) {
		testClientSideCache(t, store)
	})
}

func testBasicOperations(t *testing.T, store *RedisRefreshTokenStore) {
	ctx := context.Background()
	token := "test-token-basic"
	userData := map[string]any{
		"user_id":  123,
		"username": "testuser",
	}
	expiry := time.Now().Add(time.Hour)

	// Test Set
	err := store.Set(ctx, token, userData, expiry)
	assert.NoError(t, err, "Set should not return error")

	// Test Get
	retrievedData, err := store.Get(ctx, token)
	assert.NoError(t, err, "Get should not return error")
	assert.Equal(t, userData, retrievedData, "Retrieved data should match stored data")

	// Test Delete
	err = store.Delete(ctx, token)
	assert.NoError(t, err, "Delete should not return error")

	// Verify deletion
	_, err = store.Get(ctx, token)
	assert.ErrorIs(t, err, core.ErrRefreshTokenNotFound, "Token should not be found after deletion")

	// Test empty token
	err = store.Set(ctx, "", userData, expiry)
	assert.Error(t, err, "Set with empty token should return error")

	_, err = store.Get(ctx, "")
	assert.ErrorIs(t, err, core.ErrRefreshTokenNotFound, "Get with empty token should return not found error")

	err = store.Delete(ctx, "")
	assert.NoError(t, err, "Delete with empty token should not return error")

	// Test ping
	err = store.Ping()
	assert.NoError(t, err, "Ping should not return error")

	// Clean up test data
	_ = store.client.Do(ctx, store.client.B().Del().Key(store.buildKey(token)).Build())
}

func testExpiration(t *testing.T, store *RedisRefreshTokenStore) {
	ctx := context.Background()
	token := "test-token-expiry"
	userData := "test-data"

	// Set token with very short expiry
	shortExpiry := time.Now().Add(100 * time.Millisecond)
	err := store.Set(ctx, token, userData, shortExpiry)
	assert.NoError(t, err, "Set should not return error")

	// Token should be available immediately
	retrievedData, err := store.Get(ctx, token)
	assert.NoError(t, err, "Get should not return error immediately after set")
	assert.Equal(t, userData, retrievedData, "Retrieved data should match stored data")

	// Wait for expiration
	time.Sleep(200 * time.Millisecond)

	// Token should be expired
	_, err = store.Get(ctx, token)
	assert.ErrorIs(t, err, core.ErrRefreshTokenExpired, "Token should be expired")

	// Clean up test data
	_ = store.client.Do(ctx, store.client.B().Del().Key(store.buildKey(token)).Build())
}

func testCleanup(t *testing.T, store *RedisRefreshTokenStore) {
	ctx := context.Background()

	// Create multiple tokens with different expiration times
	tokens := []string{"cleanup-token-1", "cleanup-token-2", "cleanup-token-3"}
	userData := "cleanup-data"

	// Set tokens with past expiry (already expired)
	pastExpiry := time.Now().Add(-time.Hour)
	for _, token := range tokens[:2] {
		err := store.Set(ctx, token, userData, pastExpiry)
		assert.NoError(t, err, "Set should not return error")
	}

	// Set one token with future expiry
	futureExpiry := time.Now().Add(time.Hour)
	err := store.Set(ctx, tokens[2], userData, futureExpiry)
	assert.NoError(t, err, "Set should not return error")

	// Run cleanup
	cleaned, err := store.Cleanup(ctx)
	assert.NoError(t, err, "Cleanup should not return error")
	assert.GreaterOrEqual(t, cleaned, 0, "Cleanup should return non-negative count")

	// Verify that non-expired token still exists
	_, err = store.Get(ctx, tokens[2])
	assert.NoError(t, err, "Non-expired token should still exist after cleanup")

	// Clean up test data
	for _, token := range tokens {
		_ = store.client.Do(ctx, store.client.B().Del().Key(store.buildKey(token)).Build())
	}
}

func testCount(t *testing.T, store *RedisRefreshTokenStore) {
	ctx := context.Background()

	// Clear any existing test data first
	keys := []string{"count-token-1", "count-token-2", "count-token-3"}
	for _, key := range keys {
		_ = store.client.Do(ctx, store.client.B().Del().Key(store.buildKey(key)).Build())
	}

	// Get initial count
	initialCount, err := store.Count(ctx)
	assert.NoError(t, err, "Count should not return error")

	// Add some tokens
	userData := "count-data"
	expiry := time.Now().Add(time.Hour)

	for i, token := range keys {
		err := store.Set(ctx, token, fmt.Sprintf("%s-%d", userData, i), expiry)
		assert.NoError(t, err, "Set should not return error")
	}

	// Count should increase
	newCount, err := store.Count(ctx)
	assert.NoError(t, err, "Count should not return error")
	assert.GreaterOrEqual(t, newCount, initialCount+len(keys), "Count should include new tokens")

	// Clean up test data
	for _, token := range keys {
		err := store.Delete(ctx, token)
		assert.NoError(t, err, "Delete should not return error")
	}
}

func testClientSideCache(t *testing.T, store *RedisRefreshTokenStore) {
	ctx := context.Background()
	token := "test-token-cache"
	userData := "cache-test-data"
	expiry := time.Now().Add(time.Hour)

	// Set token
	err := store.Set(ctx, token, userData, expiry)
	assert.NoError(t, err, "Set should not return error")

	// First get (should populate cache)
	start1 := time.Now()
	retrievedData1, err := store.Get(ctx, token)
	duration1 := time.Since(start1)
	assert.NoError(t, err, "First Get should not return error")
	assert.Equal(t, userData, retrievedData1, "First retrieved data should match stored data")

	// Second get (should use cache and be faster)
	start2 := time.Now()
	retrievedData2, err := store.Get(ctx, token)
	duration2 := time.Since(start2)
	assert.NoError(t, err, "Second Get should not return error")
	assert.Equal(t, userData, retrievedData2, "Second retrieved data should match stored data")

	// Note: Cache performance test might be flaky in CI environments
	t.Logf("First get took: %v, Second get took: %v", duration1, duration2)

	// Clean up test data
	_ = store.client.Do(ctx, store.client.B().Del().Key(store.buildKey(token)).Build())
}

func TestRedisRefreshTokenStore_ConnectionFailure(t *testing.T) {
	// Test with invalid Redis configuration
	config := &RedisConfig{
		Addr:     "invalid-host:6379",
		Password: "",
		DB:       0,
	}

	_, err := NewRedisRefreshTokenStore(config)
	assert.Error(t, err, "Should return error for invalid Redis configuration")
	assert.Contains(t, err.Error(), "failed to create Redis client", "Error should mention Redis client creation failure")
}

func TestRedisRefreshTokenStore_InvalidToken(t *testing.T) {
	_, host, port := setupRedisContainer(t)

	config := &RedisConfig{
		Addr:      fmt.Sprintf("%s:%s", host, port),
		Password:  "",
		DB:        0,
		KeyPrefix: "test-jwt:",
	}

	store, err := NewRedisRefreshTokenStore(config)
	require.NoError(t, err)
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Logf("failed to close Redis store: %v", closeErr)
		}
	}()

	// Test with expired token in past
	expiredTime := time.Now().Add(-time.Hour)
	err = store.Set(context.Background(), "expired-token", "data", expiredTime)
	assert.Error(t, err, "Should return error when setting token with past expiry time")
	assert.Contains(t, err.Error(), "expiry time must be in the future", "Error should mention future expiry requirement")
}

func TestDefaultRedisConfig(t *testing.T) {
	config := DefaultRedisConfig()

	assert.Equal(t, "localhost:6379", config.Addr, "Default address should be localhost:6379")
	assert.Equal(t, "", config.Password, "Default password should be empty")
	assert.Equal(t, 0, config.DB, "Default DB should be 0")
	assert.Equal(t, 128*1024*1024, config.CacheSize, "Default cache size should be 128MB")
	assert.Equal(t, time.Minute, config.CacheTTL, "Default cache TTL should be 1 minute")
	assert.Equal(t, "gin-jwt:", config.KeyPrefix, "Default key prefix should be gin-jwt:")
}
