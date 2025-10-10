# Refresh Token Store

This package provides implementations for storing refresh tokens following RFC 6749 OAuth 2.0 standards.

## Interface

The `TokenStore` interface (from the `core` package) defines the contract for refresh token storage:

```go
import "github.com/appleboy/gin-jwt/v2/core"

type TokenStore interface {
    Set(token string, userData interface{}, expiry time.Time) error
    Get(token string) (interface{}, error)
    Delete(token string) error
    Cleanup() (int, error)
    Count() (int, error)
}
```

For backward compatibility, this package also provides type aliases:

```go
type RefreshTokenStorer = core.TokenStore
type RefreshTokenData = core.RefreshTokenData
```

## Available Implementations

### In-Memory Store

The `InMemoryRefreshTokenStore` provides a simple, thread-safe in-memory implementation:

```go
import (
    jwt "github.com/appleboy/gin-jwt/v2"
    "github.com/appleboy/gin-jwt/v2/store"
)

// Create a new in-memory store
tokenStore := store.NewInMemoryRefreshTokenStore()

// Use with JWT middleware
middleware := &jwt.GinJWTMiddleware{
    RefreshTokenStore: tokenStore,
    // ... other configuration
}
```

**Features:**

- Thread-safe operations using `sync.RWMutex`
- Automatic cleanup of expired tokens
- Suitable for single-instance applications
- No external dependencies

**Limitations:**

- Data is lost on application restart
- Not suitable for distributed systems
- Memory usage grows with number of active tokens

### Redis Store (Example)

The `RedisRefreshTokenStore` provides a Redis-based implementation:

```go
import (
    "github.com/appleboy/gin-jwt/v2/store"
    "github.com/redis/go-redis/v9"
)

// Create Redis client
client := redis.NewClient(&redis.Options{
    Addr: "localhost:6379",
})

// Create Redis store
store := store.NewRedisRefreshTokenStore(client)

// Use with JWT middleware
middleware := &jwt.GinJWTMiddleware{
    RefreshTokenStore: store,
    // ... other configuration
}
```

**Features:**

- Persistent storage
- Automatic TTL-based expiration
- Suitable for distributed systems
- High performance with Redis

**Requirements:**

- Redis server
- `github.com/redis/go-redis/v9` dependency

## Custom Implementations

You can implement your own storage backend by implementing the `core.TokenStore` interface:

```go
import "github.com/appleboy/gin-jwt/v2/core"

type DatabaseRefreshTokenStore struct {
    db *sql.DB
}

func (d *DatabaseRefreshTokenStore) Set(token string, userData interface{}, expiry time.Time) error {
    // Implementation for database storage
}

func (d *DatabaseRefreshTokenStore) Get(token string) (interface{}, error) {
    // Implementation for database retrieval
}

func (d *DatabaseRefreshTokenStore) Delete(token string) error {
    // Implementation for database deletion
}

func (d *DatabaseRefreshTokenStore) Cleanup() (int, error) {
    // Implementation for cleaning expired tokens
}

func (d *DatabaseRefreshTokenStore) Count() (int, error) {
    // Implementation for counting active tokens
}

// Ensure it implements the interface
var _ core.TokenStore = (*DatabaseRefreshTokenStore)(nil)
```

## Error Handling

The core package defines standard errors:

- `core.ErrRefreshTokenNotFound`: Token does not exist or has expired
- `core.ErrRefreshTokenExpired`: Token has expired (if applicable)

All implementations should return `core.ErrRefreshTokenNotFound` for missing or expired tokens.

For backward compatibility, these errors are also available as:

- `store.ErrRefreshTokenNotFound` = `core.ErrRefreshTokenNotFound`
- `store.ErrRefreshTokenExpired` = `core.ErrRefreshTokenExpired`

## Data Structure

The `core.RefreshTokenData` struct holds the stored token information:

```go
type RefreshTokenData struct {
    UserData interface{} `json:"user_data"`
    Expiry   time.Time   `json:"expiry"`
    Created  time.Time   `json:"created"`
}
```

This is also available as `store.RefreshTokenData` for backward compatibility.

## Testing

Run tests for all implementations:

```bash
go test -v ./store/
```

Run with coverage:

```bash
go test -v -cover ./store/
```

Run benchmarks:

```bash
go test -bench=. -benchmem ./store/
```

## Security Considerations

1. **Token Security**: Refresh tokens should be treated as sensitive data
2. **Storage Security**: Ensure your storage backend is secure and encrypted
3. **Network Security**: Use TLS/SSL for Redis connections
4. **Access Control**: Limit access to the storage backend
5. **Monitoring**: Monitor for unusual token usage patterns

## Performance Considerations

1. **In-Memory Store**:
   - Fastest for single-instance applications
   - Memory usage grows linearly with active tokens
   - Consider periodic cleanup for long-running applications

2. **Redis Store**:
   - Network latency affects performance
   - Use connection pooling for better performance
   - Consider Redis clustering for high availability

3. **Custom Stores**:
   - Implement connection pooling for database stores
   - Use prepared statements for better performance
   - Consider caching frequently accessed tokens
