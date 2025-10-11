# Token Generator Example

This example demonstrates how to use the `TokenGenerator` functionality to create JWT tokens directly without using HTTP middleware handlers.

## Features

- **Direct Token Generation**: Generate complete token pairs (access + refresh) programmatically
- **Refresh Token Management**: Handle refresh token rotation and revocation
- **RFC 6749 Compliant**: Follows OAuth 2.0 standards for token management
- **No HTTP Required**: Generate tokens without needing HTTP requests

## Usage

Run the example:

```bash
cd _example/token_generator
go run main.go
```

## Key Methods

### `TokenGenerator(userData any) (*core.Token, error)`

Generates a complete token pair containing:

- Access token (JWT)
- Refresh token (opaque)
- Token metadata (expiry, creation time, etc.)

```go
tokenPair, err := authMiddleware.TokenGenerator(userData)
if err != nil {
    log.Fatal("Failed to generate token pair:", err)
}

fmt.Printf("Access Token: %s\n", tokenPair.AccessToken)
fmt.Printf("Refresh Token: %s\n", tokenPair.RefreshToken)
fmt.Printf("Expires In: %d seconds\n", tokenPair.ExpiresIn())
```

### `TokenGeneratorWithRevocation(userData any, oldRefreshToken string) (*core.Token, error)`

Generates a new token pair and automatically revokes the old refresh token:

```go
newTokenPair, err := authMiddleware.TokenGeneratorWithRevocation(userData, oldRefreshToken)
if err != nil {
    log.Fatal("Failed to refresh token pair:", err)
}
```

## Token Structure

The `core.Token` struct contains:

```go
type Token struct {
    AccessToken  string `json:"access_token"`   // JWT access token
    TokenType    string `json:"token_type"`     // Always "Bearer"
    RefreshToken string `json:"refresh_token"`  // Opaque refresh token
    ExpiresAt    int64  `json:"expires_at"`     // Unix timestamp
    CreatedAt    int64  `json:"created_at"`     // Unix timestamp
}
```

### Utility Methods

- `ExpiresIn()` - Returns seconds until token expires
- Server-side refresh token storage and validation
- Automatic token rotation on refresh

## Use Cases

1. **Programmatic Authentication**: Generate tokens for service-to-service communication
2. **Testing**: Create tokens for testing authenticated endpoints
3. **Registration Flow**: Issue tokens immediately after user registration
4. **Background Jobs**: Generate tokens for background processing
5. **Custom Authentication**: Build custom authentication flows

## Security Features

- **Refresh Token Rotation**: Old tokens are automatically revoked
- **Server-side Storage**: Refresh tokens are stored securely server-side
- **Expiry Management**: Both access and refresh tokens have proper expiry
- **RFC 6749 Compliance**: Follows OAuth 2.0 security standards
