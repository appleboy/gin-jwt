# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**gin-jwt** is a JWT authentication middleware for the Gin web framework. It provides RFC 6749 compliant OAuth 2.0 refresh tokens with pluggable storage backends (in-memory, Redis with client-side caching). The library supports direct token generation, multiple JWT providers via dynamic key functions, and comprehensive cookie/header token management.

## Development Commands

### Testing

```bash
# Run all tests with coverage
make test

# Run tests with race detection and coverage report
go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

# Generate HTML coverage report
make coverage

# Run specific test
go test -v -run TestFunctionName ./...

# Run tests in a specific package
go test -v ./store/...
```

### Code Quality

```bash
# Format code (uses golangci-lint fmt with gofmt, gofumpt, goimports, golines)
make format

# Run linter
make lint

# Run go vet
make vet

# Clean test cache and coverage files
make clean
```

### Development Setup

```bash
# Install required development tools (golangci-lint)
make install-tools
```

### Running Examples

```bash
# Basic authentication example
go run _example/basic/server.go

# OAuth SSO integration example
go run _example/oauth_sso/server.go

# Token generator example (direct token creation)
go run _example/token_generator/main.go

# Redis store examples
go run _example/redis_simple/main.go
go run _example/redis_store/main.go
go run _example/redis_tls/main.go

# Authorization example
go run _example/authorization/main.go
```

## Architecture

### Core Components

**auth_jwt.go**: Main middleware implementation containing `GinJWTMiddleware` struct and HTTP handlers (LoginHandler, RefreshHandler, LogoutHandler, MiddlewareFunc). Handles JWT token creation, validation, and the complete authentication flow.

**core/**: Core interfaces and types

- `core/store.go`: Defines `TokenStore` interface for refresh token storage backends
- `core/token.go`: `Token` struct representing JWT token pairs with metadata

**store/**: Refresh token storage implementations

- `store/memory.go`: Thread-safe in-memory store (single-instance applications)
- `store/redis.go`: Redis-based store with rueidis client-side caching (distributed systems)
- `store/factory.go`: Factory functions for creating stores

**auth_jwt_redis.go**: Redis store configuration via functional options pattern (EnableRedisStore, WithRedisAddr, WithRedisAuth, WithRedisTLS, etc.)

### Key Architectural Patterns

**RFC 6749 OAuth 2.0 Compliance**: Uses distinct opaque refresh tokens (not JWT) stored server-side with automatic rotation on refresh for enhanced security.

**Pluggable Storage Backend**: `core.TokenStore` interface allows swapping between in-memory, Redis, or custom storage implementations without changing middleware code.

**Token Generator Pattern**: Direct token creation via `TokenGenerator()` and `TokenGeneratorWithRevocation()` methods bypasses HTTP middleware for programmatic authentication, service-to-service communication, and testing.

**Dynamic Key Function**: `KeyFunc` callback enables multi-provider JWT validation by inspecting tokens before validation and choosing appropriate signing keys/methods dynamically. This supports hybrid authentication (internal + external providers like Azure AD, Auth0).

**Functional Options for Redis**: `EnableRedisStore()` with options like `WithRedisAddr()`, `WithRedisAuth()`, `WithRedisTLS()` provides flexible configuration.

### Authentication Flow

1. **Login** (`LoginHandler`): Authenticator validates credentials → PayloadFunc creates claims → JWT access token + opaque refresh token generated → Both stored (token in store, JWT signed) → Sent via headers/cookies
2. **Protected Routes** (`MiddlewareFunc`): Token extracted from header/query/cookie → JWT validated → IdentityHandler extracts identity → Authorizer checks permissions → Request proceeds or Unauthorized called
3. **Refresh** (`RefreshHandler`): Refresh token extracted from cookie/form/query/JSON → Server-side validation → Old token revoked → New access + refresh tokens generated (token rotation) → Sent via headers/cookies
4. **Logout** (`LogoutHandler`): Refresh token extracted → Revoked from store → Cookies cleared → LogoutResponse called

### Token Storage Strategy

**Access Tokens (JWT)**: Stateless, signed, short-lived (default 1 hour), contain claims for authorization, validated cryptographically.

**Refresh Tokens (Opaque)**: Stateful, stored server-side in `TokenStore`, long-lived (default 7 days), used only to obtain new access tokens, automatically rotated on use.

**Why Separate?**: Prevents JWT refresh token vulnerabilities, enables immediate revocation, follows OAuth 2.0 security best practices, allows scalable distributed token management via Redis.

## Testing Strategy

**Unit Tests**: All main files have corresponding `*_test.go` files. Tests use `testify` for assertions and `gofight` for HTTP testing.

**Integration Tests**: Redis tests use `testcontainers-go` to spin up real Redis instances, ensuring actual Redis behavior is tested.

**Test Coverage**: Target is comprehensive coverage tracked via codecov. Run `make coverage` to see current coverage.

**Race Detection**: Tests run with `-race` flag to catch concurrency issues.

## Common Development Patterns

### Adding a New Configuration Option

1. Add field to `GinJWTMiddleware` struct in auth_jwt.go
2. Update `New()` function to handle the new field with sensible defaults
3. Document in README.md configuration table
4. Add tests in auth_jwt_test.go
5. If it's a callback function, provide example usage in \_example/

### Adding a New Storage Backend

1. Create new file in `store/` package (e.g., `store/postgres.go`)
2. Implement `core.TokenStore` interface (Set, Get, Delete, Cleanup, Count methods)
3. Add factory function in `store/factory.go`
4. Create tests (e.g., `store/postgres_test.go`) with integration tests if possible
5. Add example in `_example/` directory
6. Update README.md with configuration examples

### Modifying Token Flow

Token generation and validation logic is centralized in auth_jwt.go:

- `tokenGenerator()`: Creates access tokens (JWT)
- `generateRefreshToken()`: Creates opaque refresh tokens
- `parseToken()`: Validates and parses JWT
- `TokenGenerator()` / `TokenGeneratorWithRevocation()`: Programmatic token creation

When modifying, ensure both HTTP handler flows and direct token generation methods work correctly.

### Security Considerations

- **JWT Secret Length**: Enforce minimum 256-bit (32 bytes) secrets
- **Token Expiry**: Short-lived access tokens (15-60 min), longer refresh tokens (7 days)
- **Cookie Security**: Enable `SecureCookie`, `CookieHTTPOnly`, appropriate `SameSite` in production
- **HTTPS Only**: Always use HTTPS in production for secure cookie transmission
- **Refresh Token Rotation**: Automatically rotate refresh tokens to prevent replay attacks
- **Algorithm Validation**: Always validate signing algorithm in `KeyFunc` to prevent algorithm substitution attacks

### Implementing Multi-Provider JWT Support

Use `KeyFunc` callback to inspect token claims (especially `iss`) and return appropriate validation key:

```go
KeyFunc: func(token *jwt.Token) (interface{}, error) {
    claims := token.Claims.(jwt.MapClaims)
    issuer, _ := claims["iss"].(string)

    if isAzureADIssuer(issuer) {
        // Validate RS256, extract kid, return Azure public key
    }
    // Return own secret for internal tokens
}
```

Never chain multiple middleware instances with abort() - this creates issues. Single middleware with dynamic key function is the correct pattern.

## CI/CD

**GitHub Actions Workflows**:

- `.github/workflows/go.yml`: Runs tests on Go 1.24 and 1.25, uploads coverage to Codecov
- `.github/workflows/codeql.yml`: Security scanning
- `.github/workflows/trivy-scan.yml`: Container vulnerability scanning
- `.github/workflows/goreleaser.yml`: Release automation

**Linting**: Uses golangci-lint v2.6 with extensive ruleset (see .golangci.yml) including bodyclose, gosec, govet, staticcheck, and more. Formatters include gofmt, gofumpt, goimports, golines.

## Important Files

- `auth_jwt.go`: Main middleware (33KB, ~900 lines)
- `core/store.go`: TokenStore interface
- `core/token.go`: Token struct and metadata
- `store/memory.go`: In-memory token store
- `store/redis.go`: Redis token store with client-side caching
- `auth_jwt_redis.go`: Redis configuration helpers
- `Makefile`: Development commands
- `README.md`: Comprehensive documentation with examples

## Module Information

- **Module Path**: `github.com/appleboy/gin-jwt/v3`
- **Go Version**: 1.24+
- **Key Dependencies**:
  - `github.com/gin-gonic/gin` (web framework)
  - `github.com/golang-jwt/jwt/v5` (JWT implementation)
  - `github.com/redis/rueidis` (Redis client with client-side caching)
  - `github.com/testcontainers/testcontainers-go` (integration testing)
