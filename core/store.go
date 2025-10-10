// Package core provides core interfaces and types for gin-jwt
package core

import (
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
	Set(token string, userData interface{}, expiry time.Time) error

	// Get retrieves user data associated with a refresh token
	// Returns ErrRefreshTokenNotFound if token doesn't exist or is expired
	Get(token string) (interface{}, error)

	// Delete removes a refresh token from storage
	// Returns an error if the operation fails, but should not error if token doesn't exist
	Delete(token string) error

	// Cleanup removes expired tokens (optional, for cleanup routines)
	// Returns the number of tokens cleaned up and any error encountered
	Cleanup() (int, error)

	// Count returns the total number of active refresh tokens
	// Useful for monitoring and debugging
	Count() (int, error)
}

// RefreshTokenData holds the data stored with each refresh token
type RefreshTokenData struct {
	UserData interface{} `json:"user_data"`
	Expiry   time.Time   `json:"expiry"`
	Created  time.Time   `json:"created"`
}

// IsExpired checks if the token data has expired
func (r *RefreshTokenData) IsExpired() bool {
	return time.Now().After(r.Expiry)
}