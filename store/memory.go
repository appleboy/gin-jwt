package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/appleboy/gin-jwt/v3/core"
)

var _ core.TokenStore = &InMemoryRefreshTokenStore{}

// InMemoryRefreshTokenStore provides a simple in-memory refresh token store
// This implementation is thread-safe and suitable for single-instance applications
// For distributed systems, consider using Redis or database-based implementations
type InMemoryRefreshTokenStore struct {
	tokens map[string]*core.RefreshTokenData
	mu     sync.RWMutex
}

// NewInMemoryRefreshTokenStore creates a new in-memory refresh token store
func NewInMemoryRefreshTokenStore() *InMemoryRefreshTokenStore {
	return &InMemoryRefreshTokenStore{
		tokens: make(map[string]*core.RefreshTokenData),
	}
}

// Set stores a refresh token with associated user data and expiration
func (s *InMemoryRefreshTokenStore) Set(
	ctx context.Context,
	token string,
	userData any,
	expiry time.Time,
) error {
	if token == "" {
		return errors.New("token cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[token] = &core.RefreshTokenData{
		UserData: userData,
		Expiry:   expiry,
		Created:  time.Now(),
	}

	return nil
}

// Get retrieves user data associated with a refresh token
func (s *InMemoryRefreshTokenStore) Get(ctx context.Context, token string) (any, error) {
	if token == "" {
		return nil, ErrRefreshTokenNotFound
	}

	s.mu.RLock()
	data, exists := s.tokens[token]
	s.mu.RUnlock()

	if !exists {
		return nil, core.ErrRefreshTokenNotFound
	}

	if data.IsExpired() {
		// Clean up expired token
		s.mu.Lock()
		delete(s.tokens, token)
		s.mu.Unlock()
		return nil, core.ErrRefreshTokenNotFound
	}

	return data.UserData, nil
}

// Delete removes a refresh token from storage
func (s *InMemoryRefreshTokenStore) Delete(ctx context.Context, token string) error {
	if token == "" {
		return nil // No error for empty token deletion
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, token)
	return nil
}

// Cleanup removes expired tokens and returns the number of tokens cleaned up
func (s *InMemoryRefreshTokenStore) Cleanup(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var cleaned int
	now := time.Now()

	for token, data := range s.tokens {
		if now.After(data.Expiry) {
			delete(s.tokens, token)
			cleaned++
		}
	}

	return cleaned, nil
}

// Count returns the total number of active refresh tokens
func (s *InMemoryRefreshTokenStore) Count(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.tokens), nil
}

// GetAll returns all active tokens (for debugging/monitoring purposes)
// Note: This method is not part of the RefreshTokenStorer interface
// and should be used carefully in production environments
func (s *InMemoryRefreshTokenStore) GetAll() map[string]*core.RefreshTokenData {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Create a copy to prevent external modifications
	result := make(map[string]*core.RefreshTokenData)
	for token, data := range s.tokens {
		if !data.IsExpired() {
			result[token] = &core.RefreshTokenData{
				UserData: data.UserData,
				Expiry:   data.Expiry,
				Created:  data.Created,
			}
		}
	}

	return result
}

// Clear removes all tokens from the store (useful for testing)
// Note: This method is not part of the RefreshTokenStorer interface
func (s *InMemoryRefreshTokenStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens = make(map[string]*core.RefreshTokenData)
}
