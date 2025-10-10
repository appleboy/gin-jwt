package store

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// User represents a test user for testing purposes
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

func TestNewInMemoryRefreshTokenStore(t *testing.T) {
	store := NewInMemoryRefreshTokenStore()

	if store == nil {
		t.Fatal("NewInMemoryRefreshTokenStore returned nil")
	}

	if store.tokens == nil {
		t.Fatal("store.tokens is nil")
	}

	count, err := store.Count()
	if err != nil {
		t.Fatalf("Count() returned error: %v", err)
	}

	if count != 0 {
		t.Fatalf("Expected count to be 0, got %d", count)
	}
}

func TestInMemoryRefreshTokenStore_Set(t *testing.T) {
	store := NewInMemoryRefreshTokenStore()
	user := &User{ID: "123", Username: "testuser", Email: "test@example.com"}
	expiry := time.Now().Add(time.Hour)

	err := store.Set("token123", user, expiry)
	if err != nil {
		t.Fatalf("Set() returned error: %v", err)
	}

	count, _ := store.Count()
	if count != 1 {
		t.Fatalf("Expected count to be 1, got %d", count)
	}
}

func TestInMemoryRefreshTokenStore_SetEmptyToken(t *testing.T) {
	store := NewInMemoryRefreshTokenStore()
	user := &User{ID: "123", Username: "testuser"}
	expiry := time.Now().Add(time.Hour)

	err := store.Set("", user, expiry)
	if err == nil {
		t.Fatal("Set() should return error for empty token")
	}

	if err.Error() != "token cannot be empty" {
		t.Fatalf("Expected 'token cannot be empty' error, got: %v", err)
	}
}

func TestInMemoryRefreshTokenStore_Get(t *testing.T) {
	store := NewInMemoryRefreshTokenStore()
	user := &User{ID: "123", Username: "testuser", Email: "test@example.com"}
	expiry := time.Now().Add(time.Hour)

	// Set a token
	err := store.Set("token123", user, expiry)
	if err != nil {
		t.Fatalf("Set() returned error: %v", err)
	}

	// Get the token
	userData, err := store.Get("token123")
	if err != nil {
		t.Fatalf("Get() returned error: %v", err)
	}

	retrievedUser, ok := userData.(*User)
	if !ok {
		t.Fatal("Retrieved user data is not of type *User")
	}

	if retrievedUser.ID != user.ID || retrievedUser.Username != user.Username || retrievedUser.Email != user.Email {
		t.Fatalf("Retrieved user data doesn't match. Expected: %+v, Got: %+v", user, retrievedUser)
	}
}

func TestInMemoryRefreshTokenStore_GetNonExistent(t *testing.T) {
	store := NewInMemoryRefreshTokenStore()

	_, err := store.Get("nonexistent")
	if err != ErrRefreshTokenNotFound {
		t.Fatalf("Expected ErrRefreshTokenNotFound, got: %v", err)
	}
}

func TestInMemoryRefreshTokenStore_GetEmptyToken(t *testing.T) {
	store := NewInMemoryRefreshTokenStore()

	_, err := store.Get("")
	if err != ErrRefreshTokenNotFound {
		t.Fatalf("Expected ErrRefreshTokenNotFound for empty token, got: %v", err)
	}
}

func TestInMemoryRefreshTokenStore_GetExpired(t *testing.T) {
	store := NewInMemoryRefreshTokenStore()
	user := &User{ID: "123", Username: "testuser"}
	expiry := time.Now().Add(-time.Hour) // Expired 1 hour ago

	// Set an expired token
	err := store.Set("expired_token", user, expiry)
	if err != nil {
		t.Fatalf("Set() returned error: %v", err)
	}

	// Try to get the expired token
	_, err = store.Get("expired_token")
	if err != ErrRefreshTokenNotFound {
		t.Fatalf("Expected ErrRefreshTokenNotFound for expired token, got: %v", err)
	}

	// Verify the expired token was cleaned up
	count, _ := store.Count()
	if count != 0 {
		t.Fatalf("Expected count to be 0 after expired token cleanup, got %d", count)
	}
}

func TestInMemoryRefreshTokenStore_Delete(t *testing.T) {
	store := NewInMemoryRefreshTokenStore()
	user := &User{ID: "123", Username: "testuser"}
	expiry := time.Now().Add(time.Hour)

	// Set a token
	err := store.Set("token123", user, expiry)
	if err != nil {
		t.Fatalf("Set() returned error: %v", err)
	}

	// Delete the token
	err = store.Delete("token123")
	if err != nil {
		t.Fatalf("Delete() returned error: %v", err)
	}

	// Verify the token is gone
	_, err = store.Get("token123")
	if err != ErrRefreshTokenNotFound {
		t.Fatalf("Expected ErrRefreshTokenNotFound after deletion, got: %v", err)
	}

	count, _ := store.Count()
	if count != 0 {
		t.Fatalf("Expected count to be 0 after deletion, got %d", count)
	}
}

func TestInMemoryRefreshTokenStore_DeleteNonExistent(t *testing.T) {
	store := NewInMemoryRefreshTokenStore()

	// Should not return error for deleting non-existent token
	err := store.Delete("nonexistent")
	if err != nil {
		t.Fatalf("Delete() should not return error for non-existent token, got: %v", err)
	}
}

func TestInMemoryRefreshTokenStore_DeleteEmptyToken(t *testing.T) {
	store := NewInMemoryRefreshTokenStore()

	// Should not return error for empty token
	err := store.Delete("")
	if err != nil {
		t.Fatalf("Delete() should not return error for empty token, got: %v", err)
	}
}

func TestInMemoryRefreshTokenStore_Cleanup(t *testing.T) {
	store := NewInMemoryRefreshTokenStore()

	// Add some tokens: 2 valid, 2 expired
	validExpiry := time.Now().Add(time.Hour)
	expiredExpiry := time.Now().Add(-time.Hour)

	err := store.Set("valid1", &User{ID: "1"}, validExpiry)
	assert.NoError(t, err)
	err = store.Set("valid2", &User{ID: "2"}, validExpiry)
	assert.NoError(t, err)
	err = store.Set("expired1", &User{ID: "3"}, expiredExpiry)
	assert.NoError(t, err)
	err = store.Set("expired2", &User{ID: "4"}, expiredExpiry)
	assert.NoError(t, err)

	// Verify initial count
	count, _ := store.Count()
	if count != 4 {
		t.Fatalf("Expected initial count to be 4, got %d", count)
	}

	// Cleanup expired tokens
	cleaned, err := store.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup() returned error: %v", err)
	}

	if cleaned != 2 {
		t.Fatalf("Expected 2 tokens to be cleaned up, got %d", cleaned)
	}

	// Verify final count
	count, _ = store.Count()
	if count != 2 {
		t.Fatalf("Expected final count to be 2, got %d", count)
	}

	// Verify valid tokens still exist
	_, err = store.Get("valid1")
	if err != nil {
		t.Fatalf("valid1 token should still exist: %v", err)
	}

	_, err = store.Get("valid2")
	if err != nil {
		t.Fatalf("valid2 token should still exist: %v", err)
	}

	// Verify expired tokens are gone
	_, err = store.Get("expired1")
	if err != ErrRefreshTokenNotFound {
		t.Fatalf("expired1 token should be gone: %v", err)
	}

	_, err = store.Get("expired2")
	if err != ErrRefreshTokenNotFound {
		t.Fatalf("expired2 token should be gone: %v", err)
	}
}

func TestInMemoryRefreshTokenStore_Count(t *testing.T) {
	store := NewInMemoryRefreshTokenStore()

	// Initially empty
	count, err := store.Count()
	if err != nil {
		t.Fatalf("Count() returned error: %v", err)
	}
	if count != 0 {
		t.Fatalf("Expected initial count to be 0, got %d", count)
	}

	// Add tokens
	expiry := time.Now().Add(time.Hour)
	for i := 0; i < 5; i++ {
		token := fmt.Sprintf("token%d", i)
		user := &User{ID: fmt.Sprintf("%d", i)}
		_ = store.Set(token, user, expiry)
	}

	count, err = store.Count()
	if err != nil {
		t.Fatalf("Count() returned error: %v", err)
	}
	if count != 5 {
		t.Fatalf("Expected count to be 5, got %d", count)
	}
}

func TestInMemoryRefreshTokenStore_GetAll(t *testing.T) {
	store := NewInMemoryRefreshTokenStore()

	// Add some tokens
	validExpiry := time.Now().Add(time.Hour)
	expiredExpiry := time.Now().Add(-time.Hour)

	_ = store.Set("valid1", &User{ID: "1"}, validExpiry)
	_ = store.Set("valid2", &User{ID: "2"}, validExpiry)
	_ = store.Set("expired1", &User{ID: "3"}, expiredExpiry)

	all := store.GetAll()

	// Should only return valid tokens
	if len(all) != 2 {
		t.Fatalf("Expected 2 valid tokens, got %d", len(all))
	}

	if _, exists := all["valid1"]; !exists {
		t.Fatal("valid1 should be in GetAll() result")
	}

	if _, exists := all["valid2"]; !exists {
		t.Fatal("valid2 should be in GetAll() result")
	}

	if _, exists := all["expired1"]; exists {
		t.Fatal("expired1 should not be in GetAll() result")
	}
}

func TestInMemoryRefreshTokenStore_Clear(t *testing.T) {
	store := NewInMemoryRefreshTokenStore()

	// Add some tokens
	expiry := time.Now().Add(time.Hour)
	_ = store.Set("token1", &User{ID: "1"}, expiry)
	_ = store.Set("token2", &User{ID: "2"}, expiry)

	count, _ := store.Count()
	if count != 2 {
		t.Fatalf("Expected count to be 2, got %d", count)
	}

	// Clear all tokens
	store.Clear()

	count, _ = store.Count()
	if count != 0 {
		t.Fatalf("Expected count to be 0 after Clear(), got %d", count)
	}
}

// TestInMemoryRefreshTokenStore_ConcurrentAccess tests thread safety
func TestInMemoryRefreshTokenStore_ConcurrentAccess(t *testing.T) {
	store := NewInMemoryRefreshTokenStore()
	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrent writes
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			token := fmt.Sprintf("token%d", id)
			user := &User{ID: fmt.Sprintf("%d", id)}
			expiry := time.Now().Add(time.Hour)
			_ = store.Set(token, user, expiry)
		}(i)
	}
	wg.Wait()

	// Verify all tokens were added
	count, _ := store.Count()
	if count != numGoroutines {
		t.Fatalf("Expected count to be %d, got %d", numGoroutines, count)
	}

	// Concurrent reads
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			token := fmt.Sprintf("token%d", id)
			_, err := store.Get(token)
			if err != nil {
				t.Errorf("Failed to get token%d: %v", id, err)
			}
		}(i)
	}
	wg.Wait()

	// Concurrent deletes
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			token := fmt.Sprintf("token%d", id)
			_ = store.Delete(token)
		}(i)
	}
	wg.Wait()

	// Verify all tokens were deleted
	count, _ = store.Count()
	if count != 0 {
		t.Fatalf("Expected count to be 0 after concurrent deletes, got %d", count)
	}
}

func TestRefreshTokenData_IsExpired(t *testing.T) {
	// Test non-expired token
	data := &RefreshTokenData{
		UserData: &User{ID: "123"},
		Expiry:   time.Now().Add(time.Hour),
		Created:  time.Now(),
	}

	if data.IsExpired() {
		t.Fatal("Token should not be expired")
	}

	// Test expired token
	data.Expiry = time.Now().Add(-time.Hour)
	if !data.IsExpired() {
		t.Fatal("Token should be expired")
	}
}

// Benchmark tests
func BenchmarkInMemoryRefreshTokenStore_Set(b *testing.B) {
	store := NewInMemoryRefreshTokenStore()
	user := &User{ID: "123", Username: "testuser"}
	expiry := time.Now().Add(time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token := fmt.Sprintf("token%d", i)
		_ = store.Set(token, user, expiry)
	}
}

func BenchmarkInMemoryRefreshTokenStore_Get(b *testing.B) {
	store := NewInMemoryRefreshTokenStore()
	user := &User{ID: "123", Username: "testuser"}
	expiry := time.Now().Add(time.Hour)

	// Pre-populate with tokens
	for i := 0; i < 1000; i++ {
		token := fmt.Sprintf("token%d", i)
		_ = store.Set(token, user, expiry)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token := fmt.Sprintf("token%d", i%1000)
		_, _ = store.Get(token)
	}
}

func BenchmarkInMemoryRefreshTokenStore_Delete(b *testing.B) {
	store := NewInMemoryRefreshTokenStore()
	user := &User{ID: "123", Username: "testuser"}
	expiry := time.Now().Add(time.Hour)

	// Pre-populate with tokens
	for i := 0; i < b.N; i++ {
		token := fmt.Sprintf("token%d", i)
		_ = store.Set(token, user, expiry)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token := fmt.Sprintf("token%d", i)
		_ = store.Delete(token)
	}
}