// Package store provides implementations for refresh token storage
package store

import (
	"github.com/appleboy/gin-jwt/v2/core"
)

// Re-export types from core for backward compatibility
type RefreshTokenStorer = core.TokenStore
type RefreshTokenData = core.RefreshTokenData

// Re-export errors from core for backward compatibility
var (
	ErrRefreshTokenNotFound = core.ErrRefreshTokenNotFound
	ErrRefreshTokenExpired  = core.ErrRefreshTokenExpired
)

// Default creates a default memory-based token store
// This is the recommended way to create a store with sensible defaults
func Default() core.TokenStore {
	return NewMemoryStore()
}