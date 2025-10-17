// Package core provides core interfaces and types for gin-jwt
package core

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrRefreshTokenNotFound indicates the refresh token was not found in storage
	ErrRefreshTokenNotFound = errors.New("refresh token not found")

	// ErrRefreshTokenExpired indicates the refresh token has expired
	ErrRefreshTokenExpired = errors.New("refresh token expired")
)

// TokenStore defines the interface for storing and retrieving refresh tokens
type TokenStore interface {
	// Set stores a refresh token with associated user data and expiration
	// Returns an error if the operation fails
	Set(ctx context.Context, token string, userData any, expiry time.Time) error

	// Get retrieves user data associated with a refresh token
	// Returns ErrRefreshTokenNotFound if token doesn't exist or is expired
	Get(ctx context.Context, token string) (any, error)

	// Delete removes a refresh token from storage
	// Returns an error if the operation fails, but should not error if token doesn't exist
	Delete(ctx context.Context, token string) error

	// Cleanup removes expired tokens (optional, for cleanup routines)
	// Returns the number of tokens cleaned up and any error encountered
	Cleanup(ctx context.Context) (int, error)

	// Count returns the total number of active refresh tokens
	// Useful for monitoring and debugging
	Count(ctx context.Context) (int, error)
}

// RefreshTokenData holds the data stored with each refresh token
type RefreshTokenData struct {
	UserData any       `json:"user_data"`
	Expiry   time.Time `json:"expiry"`
	Created  time.Time `json:"created"`
}

// IsExpired checks if the token data has expired
func (r *RefreshTokenData) IsExpired() bool {
	return time.Now().After(r.Expiry)
}

// Token represents a complete JWT token pair with metadata
type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at"`
	CreatedAt    int64  `json:"created_at"`
}

// ExpiresIn returns the number of seconds until the access token expires
func (t *Token) ExpiresIn() int64 {
	return t.ExpiresAt - time.Now().Unix()
}
