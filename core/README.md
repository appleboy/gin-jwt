# Core Package

The core package provides fundamental interfaces and types for gin-jwt.

## TokenStore Interface

The `TokenStore` interface defines the contract for refresh token storage:

```go
type TokenStore interface {
    // Set stores a refresh token with associated user data and expiration
    Set(token string, userData interface{}, expiry time.Time) error

    // Get retrieves user data associated with a refresh token
    // Returns ErrRefreshTokenNotFound if token doesn't exist or is expired
    Get(token string) (interface{}, error)

    // Delete removes a refresh token from storage
    Delete(token string) error

    // Cleanup removes expired tokens (optional, for cleanup routines)
    // Returns the number of tokens cleaned up and any error encountered
    Cleanup() (int, error)

    // Count returns the total number of active refresh tokens
    Count() (int, error)
}
```

## RefreshTokenData

The `RefreshTokenData` struct holds the data stored with each refresh token:

```go
type RefreshTokenData struct {
    UserData interface{} `json:"user_data"`
    Expiry   time.Time   `json:"expiry"`
    Created  time.Time   `json:"created"`
}

// IsExpired checks if the token data has expired
func (r *RefreshTokenData) IsExpired() bool
```

## Error Types

Standard error types for token operations:

```go
var (
    // ErrRefreshTokenNotFound indicates the refresh token was not found in storage
    ErrRefreshTokenNotFound = errors.New("refresh token not found")

    // ErrRefreshTokenExpired indicates the refresh token has expired
    ErrRefreshTokenExpired = errors.New("refresh token expired")
)
```

## Usage

This package is typically used by storage implementations:

```go
import (
    "github.com/appleboy/gin-jwt/v2/core"
    "time"
)

// Example implementation
type MyTokenStore struct {
    // Your storage backend
}

func (m *MyTokenStore) Set(token string, userData interface{}, expiry time.Time) error {
    // Store the token using core.RefreshTokenData
    data := &core.RefreshTokenData{
        UserData: userData,
        Expiry:   expiry,
        Created:  time.Now(),
    }
    // ... your storage logic
    return nil
}

func (m *MyTokenStore) Get(token string) (interface{}, error) {
    // Retrieve and check for core.ErrRefreshTokenNotFound
    // ... your retrieval logic
    if tokenNotFound {
        return nil, core.ErrRefreshTokenNotFound
    }
    return userData, nil
}

// ... implement other methods

// Ensure it satisfies the interface
var _ core.TokenStore = (*MyTokenStore)(nil)
```

## Design Principles

1. **Separation of Concerns**: Core interfaces separate from implementation details
2. **Backward Compatibility**: Stable API that won't break existing code
3. **Extensibility**: Easy to implement custom storage backends
4. **Type Safety**: Clear contracts through interfaces
5. **Error Handling**: Standardized error types for consistent behavior

## See Also

- [store package](../store/README.md) - Pre-built storage implementations
