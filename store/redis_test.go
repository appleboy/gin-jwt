package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/appleboy/gin-jwt/v3/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/redis"
)

func setupRedisContainer(t *testing.T) (string, string) {
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

	return host, mappedPort.Port()
}

func TestRedisRefreshTokenStore_Integration(t *testing.T) {
	host, port := setupRedisContainer(t)

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

	t.Run("RepeatedReadsAndRevocation", func(t *testing.T) {
		testRepeatedReadsAndRevocation(t, store)
	})
}

func testBasicOperations(t *testing.T, store *RedisRefreshTokenStore) {
	ctx := context.Background()
	token := "test-token-basic"
	userData := map[string]any{
		"user_id":  float64(123),
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
	assert.ErrorIs(
		t,
		err,
		core.ErrRefreshTokenNotFound,
		"Get with empty token should return not found error",
	)

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
	token := "test-token-expiry" // #nosec G101 -- This is a test token identifier, not a credential
	userData := "test-data"

	// Set token with very short expiry
	shortExpiry := time.Now().Add(500 * time.Millisecond)
	err := store.Set(ctx, token, userData, shortExpiry)
	require.NoError(t, err, "Set should support subsecond expiration")

	// Token should be available immediately
	retrievedData, err := store.Get(ctx, token)
	assert.NoError(t, err, "Get should not return error immediately after set")
	assert.Equal(t, userData, retrievedData, "Retrieved data should match stored data")

	// Redis removes expired keys, so the store reports them as not found.
	require.Eventually(t, func() bool {
		_, getErr := store.Get(ctx, token)
		return errors.Is(getErr, core.ErrRefreshTokenNotFound)
	}, 3*time.Second, 10*time.Millisecond, "Redis should evict the expired token")

	// Clean up test data
	_ = store.client.Do(ctx, store.client.B().Del().Key(store.buildKey(token)).Build())
}

func testCleanup(t *testing.T, store *RedisRefreshTokenStore) {
	ctx := context.Background()

	// Create multiple tokens with different expiration times
	tokens := []string{"cleanup-token-1", "cleanup-token-2", "cleanup-token-3"}
	userData := "cleanup-data"

	// Seed expired data directly because Set rejects past expiry times.
	data, err := json.Marshal(&core.RefreshTokenData{
		UserData: userData,
		Expiry:   time.Now().Add(-time.Hour),
		Created:  time.Now().Add(-2 * time.Hour),
	})
	require.NoError(t, err)
	for _, token := range tokens[:2] {
		cmd := store.client.B().Set().Key(store.buildKey(token)).Value(string(data)).Build()
		require.NoError(t, store.client.Do(ctx, cmd).Error())
	}

	// Set one token with future expiry
	futureExpiry := time.Now().Add(time.Hour)
	err = store.Set(ctx, tokens[2], userData, futureExpiry)
	assert.NoError(t, err, "Set should not return error")

	// Run cleanup
	cleaned, err := store.Cleanup(ctx)
	assert.NoError(t, err, "Cleanup should not return error")
	assert.Equal(t, 2, cleaned, "Cleanup should remove both expired tokens")

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

func testRepeatedReadsAndRevocation(t *testing.T, store *RedisRefreshTokenStore) {
	ctx := context.Background()
	token := t.Name()
	userData := "revocation-test-data"

	for range 20 {
		require.NoError(t, store.Set(ctx, token, userData, time.Now().Add(time.Hour)))
		for range 2 {
			retrievedData, err := store.Get(ctx, token)
			require.NoError(t, err)
			require.Equal(t, userData, retrievedData)
		}

		require.NoError(t, store.Delete(ctx, token))
		_, err := store.Get(ctx, token)
		require.ErrorIs(t, err, core.ErrRefreshTokenNotFound,
			"a revoked token must not be returned by a subsequent read")
	}
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
	assert.Contains(
		t,
		err.Error(),
		"failed to create Redis client",
		"Error should mention Redis client creation failure",
	)
}

func TestRedisRefreshTokenStore_InvalidToken(t *testing.T) {
	host, port := setupRedisContainer(t)

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
	assert.Contains(
		t,
		err.Error(),
		"expiry time must be in the future",
		"Error should mention future expiry requirement",
	)
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
