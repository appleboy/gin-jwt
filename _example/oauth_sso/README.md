# OAuth SSO Integration Example

This example demonstrates how to integrate OAuth 2.0 SSO (Single Sign-On) with gin-jwt, supporting multiple identity providers.

## Features

- Support for multiple OAuth providers (Google, GitHub)
- OAuth 2.0 Authorization Code Flow
- CSRF protection (using state tokens)
- JWT token generation and management
- **Secure httpOnly cookie-based authentication**
- Token refresh mechanism
- Protected API endpoints
- Automatic cleanup of expired state tokens

## Quick Start

The fastest way to test this example:

```bash
# 1. Navigate to the example directory
cd _example/oauth_sso

# 2. Install dependencies
go mod download

# 3. Run without OAuth (view API structure only)
go run server.go

# 4. Visit the demo page
open http://localhost:8000/demo
```

For full OAuth functionality, follow the setup steps below.

## Requirements

- Go 1.24 or higher
- Google OAuth 2.0 credentials (if using Google login)
- GitHub OAuth App credentials (if using GitHub login)

## Setup Steps

### 1. Create OAuth Applications

#### Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable "Google+ API"
4. Navigate to "Credentials"
5. Create "OAuth 2.0 Client ID"
6. Select "Web application" as application type
7. Add authorized redirect URI: `http://localhost:8000/auth/google/callback`
8. Note down the Client ID and Client Secret

#### GitHub OAuth Setup

1. Go to [GitHub Settings > Developer settings > OAuth Apps](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in application information:
   - Application name: Your application name
   - Homepage URL: `http://localhost:8000`
   - Authorization callback URL: `http://localhost:8000/auth/github/callback`
4. Click "Register application"
5. Note down the Client ID and Client Secret

### 2. Set Environment Variables

Create a `.env` file or set environment variables in terminal:

```bash
# Google OAuth (Optional)
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"

# GitHub OAuth (Optional)
export GITHUB_CLIENT_ID="your-github-client-id"
export GITHUB_CLIENT_SECRET="your-github-client-secret"

# JWT Secret Key (recommended to use strong password in production)
export JWT_SECRET_KEY="your-secret-key-here"

# Server Port (optional, default is 8000)
export PORT="8000"
```

### 3. Install Dependencies

```bash
go mod download
```

### 4. Run the Example

```bash
go run server.go
# or use Makefile
make run
```

The server will start at `http://localhost:8000`

### 5. Use the Demo Page

Visit `http://localhost:8000/demo` to use the built-in interactive demo page:

- Graphical interface
- One-click login
- Automatic token management
- Real-time testing of all API features

The demo page provides the easiest way to test!

## API Endpoints

### Public Endpoints

- `GET /` - Home page, displays available endpoints
- `GET /auth/google/login` - Initiate Google OAuth login flow
- `GET /auth/github/login` - Initiate GitHub OAuth login flow
- `GET /auth/google/callback` - Google OAuth callback endpoint
- `GET /auth/github/callback` - GitHub OAuth callback endpoint
- `POST /auth/refresh` - Refresh JWT token

### Protected Endpoints (Requires JWT token)

- `GET /api/profile` - Get user profile
- `POST /api/logout` - Logout

## Usage Flow

### 1. User Login

Visit the login URL:

```bash
# Google login
curl http://localhost:8000/auth/google/login

# GitHub login
curl http://localhost:8000/auth/github/login
```

The browser will redirect to the OAuth provider's authorization page.

### 2. Obtain JWT Token After Authorization

After user authorization, they will be redirected to the demo page. The server provides the JWT token via **two methods**:

1. **httpOnly Cookie** - Automatically set by the server (for browser apps)
2. **Authorization Header** - Included in the response (for API clients/mobile apps)

The callback URL will be:

```bash
/demo?provider=google  (or github)
```

**Dual Token Delivery**:

For **browser applications**:

- Token stored in httpOnly cookie (prevents XSS attacks)
- Automatically sent with same-origin requests
- No JavaScript handling needed

For **mobile/desktop apps**:

- Token available in `Authorization` response header
- Format: `Authorization: Bearer <jwt_token>`
- Client can extract and store securely

Token structure (RFC 6749 OAuth 2.0 standard format):

- `access_token`: JWT access token
- `token_type`: Token type (usually "Bearer")
- `refresh_token`: Refresh token (used to refresh access token)
- `expires_at`: Unix timestamp, token expiration time

The demo page automatically handles cookie-based authentication.

### 3. Access Protected APIs with Token

The JWT token can be sent via:

1. **Cookie** (automatic with browser requests)
2. **Authorization header** (for API clients)
3. **Query parameter** (not recommended for security)

Using curl with Authorization header:

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:8000/api/profile
```

Using curl with cookie (after login):

```bash
curl --cookie-jar cookies.txt --cookie cookies.txt \
  http://localhost:8000/api/profile
```

Response:

```json
{
  "code": 200,
  "user": {
    "id": "google_123456",
    "email": "user@example.com",
    "name": "User Name",
    "provider": "google",
    "avatar_url": "https://..."
  },
  "claims": {
    "id": "google_123456",
    "email": "user@example.com",
    "name": "User Name",
    "provider": "google",
    "avatar": "https://...",
    "exp": 1704110400,
    "iat": 1704106800
  }
}
```

### 4. Refresh Token

When the access token is about to expire, you can use the refresh endpoint (requires a valid access token):

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8000/auth/refresh
```

Response format:

```json
{
  "access_token": "new_token_here",
  "token_type": "Bearer",
  "refresh_token": "new_refresh_token_here",
  "expires_at": 1704110400,
  "created_at": 1704106800
}
```

### 5. Logout

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:8000/api/logout
```

## Cookie-Based Authentication

This example uses **httpOnly cookies** and **Authorization headers** for enhanced security and flexibility. The configuration is in `initJWTParams()`:

```go
SendCookie:        true,           // Enable automatic cookie handling
CookieHTTPOnly:    true,           // Prevent JavaScript access (XSS protection)
SecureCookie:      false,          // Set to true in production with HTTPS
CookieMaxAge:      time.Hour,      // Cookie expiration
SendAuthorization: true,           // Send Authorization header in response
TokenLookup:       "header: Authorization, query: token, cookie: jwt",
```

### Dual Authentication Support

This example supports both authentication methods:

1. **httpOnly Cookie** (Enabled via `SendCookie: true`)

   - Automatically set by server on login
   - Cannot be accessed by JavaScript (XSS protection)
   - Automatically sent with same-origin requests
   - Best for browser-based applications

2. **Authorization Header** (Enabled via `SendAuthorization: true`)
   - Included in LoginResponse: `Authorization: Bearer <token>`
   - Can be extracted by client applications
   - Best for mobile apps and API clients
   - Traditional REST API approach

### Why httpOnly Cookies?

✅ **XSS Protection**: JavaScript cannot access the token
✅ **Automatic**: Cookies sent automatically with same-origin requests
✅ **Secure**: Better than localStorage or URL parameters
✅ **CSRF Protected**: Combined with state tokens for OAuth flow

### Why Authorization Header?

✅ **API Clients**: Easy to integrate with mobile/desktop apps
✅ **Flexibility**: Client controls token storage
✅ **Standard**: RESTful API convention
✅ **Cross-Domain**: Works with CORS without credentials

### Browser vs API Clients

- **Browser (Web App)**: Uses cookies automatically (no JavaScript needed)
- **Mobile Apps**: Extract token from Authorization header, store securely
- **API Clients**: Use Authorization header for requests
- **Hybrid Apps**: Can use either method based on preference

## Security Considerations

### CSRF Protection

- Uses randomly generated state tokens to prevent CSRF attacks
- State tokens have a 10-minute validity period
- Tokens are immediately deleted after verification

### Token Management

- JWT tokens use HS256 signing algorithm
- Tokens have a 1-hour validity period
- Can be refreshed within 24 hours
- Stored in httpOnly cookies (cannot be accessed by JavaScript)
- Recommended to use environment variables for strong passwords in production

### Best Practices

1. **Use HTTPS**: Must use HTTPS in production environments (set `SecureCookie: true`)
2. **Environment Variables**: Don't hardcode secrets in code
3. **httpOnly Cookies**: Already enabled for XSS protection
4. **Token Storage**: Consider using Redis or other storage mechanisms to manage tokens
5. **Refresh Token**: Consider implementing refresh token rotation mechanism
6. **Scope Limitation**: Only request necessary OAuth scopes
7. **Error Handling**: Properly handle various error conditions

## Integrating Other OAuth Providers

This example can be easily extended to support other OAuth 2.0 providers, such as:

- Microsoft Azure AD
- Facebook
- Twitter
- LinkedIn
- Custom OAuth 2.0 servers

You just need to:

1. Add OAuth configuration
2. Implement login and callback handlers
3. Handle provider-specific user information format

## Advanced Features

### Multi-Provider User Merging

If you need to link a user's different OAuth accounts (e.g., Google and GitHub) together, you can:

1. Use email as a unique identifier
2. Store user associations with multiple OAuth providers in the database
3. Allow users to link multiple accounts in settings

### Token Revocation

To implement server-side token revocation, you can integrate Redis store:

```go
import "github.com/appleboy/gin-jwt/v3/store/redis"

// Add in initJWTParams()
TokenStore: redis.NewStore(...),
```

Refer to the `redis_store` example for more details.

## Troubleshooting

### OAuth Callback Failure

- Ensure redirect URI matches OAuth application settings
- Check if Client ID and Secret are correct
- Check browser developer tools network requests

### Invalid Token

- Ensure JWT_SECRET_KEY remains consistent after restart
- Check if token has expired
- Verify Authorization header format: `Bearer <token>`

### Cannot Get User Email

- GitHub: Ensure `user:email` is requested in OAuth scope
- Some users may hide their email, requiring additional handling

## Resources

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [GitHub OAuth Documentation](https://docs.github.com/en/developers/apps/building-oauth-apps)
- [JWT RFC 7519](https://tools.ietf.org/html/rfc7519)
- [gin-jwt Project](https://github.com/appleboy/gin-jwt)
