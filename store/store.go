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