# Redis Store Example

This example demonstrates how to use Redis store with gin-jwt middleware using the new convenience methods.

## Features

- **Redis Integration**: Use Redis as the backend store for refresh tokens
- **Client-side Caching**: Built-in client-side caching for improved performance
- **Automatic Fallback**: Falls back to in-memory store if Redis connection fails
- **Easy Configuration**: Simple methods to configure Redis store

## Usage

### Method 1: Enable Redis with Default Configuration

```go
middleware := &jwt.GinJWTMiddleware{
    // ... other configuration
    UseRedisStore: true,
}

// Or using convenience method
middleware.EnableRedisStore()
```

### Method 2: Enable Redis with Custom Address

```go
middleware.EnableRedisStoreWithAddr("localhost:6379")
```

### Method 3: Enable Redis with Full Options

```go
middleware.EnableRedisStoreWithOptions("localhost:6379", "password", 0)
```

### Method 4: Enable Redis with Custom Configuration

```go
config := store.DefaultRedisConfig()
config.Addr = "localhost:6379"
config.CacheSize = 128 * 1024 * 1024 // 128MB
middleware.EnableRedisStoreWithConfig(config)
```

### Method 5: Configure Client-side Cache

```go
middleware.SetRedisClientSideCache(64*1024*1024, 30*time.Second) // 64MB cache, 30s TTL
```

## Running the Example

1. Start Redis server (optional - will fall back to memory store if not available):

   ```bash
   redis-server
   ```

2. Run the example:

   ```bash
   go run main.go
   ```

3. Test the endpoints:

   ```bash
   # Login
   curl -X POST localhost:8000/login -d '{"username": "admin", "password": "admin"}' -H "Content-Type: application/json"

   # Use the returned token in subsequent requests
   curl -H "Authorization: Bearer YOUR_TOKEN" localhost:8000/auth/hello

   # Refresh token
   curl -X GET localhost:8000/auth/refresh_token -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}' -H "Content-Type: application/json"
   ```

## Configuration Options

### RedisConfig

- `Addr`: Redis server address (default: "localhost:6379")
- `Password`: Redis password (default: "")
- `DB`: Redis database number (default: 0)
- `CacheSize`: Client-side cache size in bytes (default: 128MB)
- `CacheTTL`: Client-side cache TTL (default: 1 minute)
- `KeyPrefix`: Prefix for all Redis keys (default: "gin-jwt:")

### Fallback Behavior

If Redis connection fails during initialization:

- The middleware logs an error message
- Automatically falls back to in-memory store
- Application continues to function normally

This ensures high availability and prevents application failures due to Redis connectivity issues.
