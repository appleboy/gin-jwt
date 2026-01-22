package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/appleboy/gin-jwt/v3/core"
	"github.com/appleboy/gin-jwt/v3/store"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/youmark/pkcs8"
)

// GinJWTMiddleware provides a Json-Web-Token authentication implementation. On failure, a 401 HTTP response
// is returned. On success, the wrapped middleware is called, and the userID is made available as
// c.Get("userID").(string).
// Users can get a token by posting a json request to LoginHandler. The token then needs to be passed in
// the Authentication header. Example: Authorization:Bearer XXX_TOKEN_XXX
type GinJWTMiddleware struct {
	// Realm name to display to the user. Required.
	Realm string

	// signing algorithm - possible values are HS256, HS384, HS512, RS256, RS384 or RS512
	// Optional, default is HS256.
	SigningAlgorithm string

	// Secret key used for signing. Required.
	Key []byte

	// Callback to retrieve key used for signing. Setting KeyFunc will bypass
	// all other key settings
	KeyFunc func(token *jwt.Token) (any, error)

	// Duration that a jwt token is valid. Optional, defaults to one hour.
	Timeout time.Duration
	// Callback function that will override the default timeout duration.
	TimeoutFunc func(data any) time.Duration

	// This field allows clients to refresh their token until MaxRefresh has passed.
	// Note that clients can refresh their token in the last moment of MaxRefresh.
	// This means that the maximum validity timespan for a token is TokenTime + MaxRefresh.
	// Optional, defaults to 0 meaning not refreshable.
	MaxRefresh time.Duration

	// Callback function that should perform the authentication of the user based on login info.
	// Must return user data as user identifier, it will be stored in Claim Array. Required.
	// Check error (e) to determine the appropriate error message.
	Authenticator func(c *gin.Context) (any, error)

	// Callback function that should perform the authorization of the authenticated user. Called
	// only after an authentication success. Must return true on success, false on failure.
	// Optional, default to success.
	Authorizer func(c *gin.Context, data any) bool

	// Callback function that will be called during login.
	// Using this function it is possible to add additional payload data to the webtoken.
	// The data is then made available during requests via c.Get("JWT_PAYLOAD").
	// Note that the payload is not encrypted.
	// The attributes mentioned on jwt.io can't be used as keys for the map.
	// Optional, by default no additional data will be set.
	PayloadFunc func(data any) jwt.MapClaims

	// User can define own Unauthorized func.
	Unauthorized func(c *gin.Context, code int, message string)

	// User can define own LoginResponse func.
	LoginResponse func(c *gin.Context, token *core.Token)

	// User can define own LogoutResponse func.
	LogoutResponse func(c *gin.Context)

	// User can define own RefreshResponse func.
	RefreshResponse func(c *gin.Context, token *core.Token)

	// Set the identity handler function
	IdentityHandler func(*gin.Context) any

	// Set the identity key
	IdentityKey string

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "cookie:<name>"
	TokenLookup string

	// TokenHeadName is a string in the header. Default value is "Bearer"
	TokenHeadName string

	// TimeFunc provides the current time. You can override it to use another time value. This is useful for testing or if your server uses a different time zone than your tokens.
	TimeFunc func() time.Time

	// HTTP Status messages for when something in the JWT middleware fails.
	// Check error (e) to determine the appropriate error message.
	HTTPStatusMessageFunc func(c *gin.Context, e error) string

	// Private key file for asymmetric algorithms
	PrivKeyFile string

	// Private Key bytes for asymmetric algorithms
	//
	// Note: PrivKeyFile takes precedence over PrivKeyBytes if both are set
	PrivKeyBytes []byte

	// Public key file for asymmetric algorithms
	PubKeyFile string

	// Private key passphrase
	PrivateKeyPassphrase string

	// Public key bytes for asymmetric algorithms.
	//
	// Note: PubKeyFile takes precedence over PubKeyBytes if both are set
	PubKeyBytes []byte

	// Private key
	privKey *rsa.PrivateKey

	// Public key
	pubKey *rsa.PublicKey

	// Optionally return the token as a cookie
	SendCookie bool

	// Duration that a cookie is valid. Optional, by default equals to Timeout value.
	CookieMaxAge time.Duration

	// Allow insecure cookies for development over http
	SecureCookie bool

	// Allow cookies to be accessed client side for development
	CookieHTTPOnly bool

	// Allow cookie domain change for development
	CookieDomain string

	// SendAuthorization allow return authorization header for every request
	SendAuthorization bool

	// Disable abort() of context.
	DisabledAbort bool

	// CookieName allow cookie name change for development
	CookieName string

	// RefreshTokenCookieName allow refresh token cookie name change for development
	RefreshTokenCookieName string

	// CookieSameSite allow use http.SameSite cookie param
	CookieSameSite http.SameSite

	// ParseOptions allow to modify jwt's parser methods.
	// WithTimeFunc is always added to ensure the TimeFunc is propagated to the validator
	ParseOptions []jwt.ParserOption

	// Default value is "exp"
	ExpField string

	// RefreshTokenTimeout specifies how long refresh tokens are valid
	// Defaults to 30 days if not set
	RefreshTokenTimeout time.Duration

	// RefreshTokenStore interface for storing and retrieving refresh tokens
	// If nil, an in-memory store will be used
	RefreshTokenStore core.TokenStore

	// RefreshTokenLength specifies the byte length of refresh tokens (default: 32)
	RefreshTokenLength int

	// UseRedisStore indicates whether to use Redis store instead of in-memory store
	// When true, will attempt to connect to Redis using RedisConfig
	UseRedisStore bool

	// RedisConfig configuration for Redis store when UseRedisStore is true
	// If nil when UseRedisStore is true, will use default Redis configuration
	RedisConfig *store.RedisConfig

	// inMemoryStore internal fallback refresh token store
	inMemoryStore *store.InMemoryRefreshTokenStore
}

var (
	// ErrMissingSecretKey indicates Secret key is required
	ErrMissingSecretKey = errors.New("secret key is required")

	// ErrForbidden when HTTP status 403 is given
	ErrForbidden = errors.New("you don't have permission to access this resource")

	// ErrMissingAuthenticatorFunc indicates Authenticator is required
	ErrMissingAuthenticatorFunc = errors.New("ginJWTMiddleware.Authenticator func is undefined")

	// ErrMissingLoginValues indicates a user tried to authenticate without username or password
	ErrMissingLoginValues = errors.New("missing Username or Password")

	// ErrFailedAuthentication indicates authentication failed, could be faulty username or password
	ErrFailedAuthentication = errors.New("incorrect Username or Password")

	// ErrFailedTokenCreation indicates JWT Token failed to create, reason unknown
	ErrFailedTokenCreation = errors.New("failed to create JWT Token")

	// ErrExpiredToken indicates JWT token has expired. Can't refresh.
	ErrExpiredToken = errors.New(
		"token is expired",
	) // in practice, this is generated from the jwt library not by us

	// ErrEmptyAuthHeader can be thrown if authing with a HTTP header, the Auth header needs to be set
	ErrEmptyAuthHeader = errors.New("auth header is empty")

	// ErrMissingExpField missing exp field in token
	ErrMissingExpField = errors.New("missing exp field")

	// ErrWrongFormatOfExp field must be float64 format
	ErrWrongFormatOfExp = errors.New("exp must be float64 format")

	// ErrInvalidAuthHeader indicates auth header is invalid, could for example have the wrong Realm name
	ErrInvalidAuthHeader = errors.New("auth header is invalid")

	// ErrEmptyQueryToken can be thrown if authing with URL Query, the query token variable is empty
	ErrEmptyQueryToken = errors.New("query token is empty")

	// ErrEmptyCookieToken can be thrown if authing with a cookie, the token cookie is empty
	ErrEmptyCookieToken = errors.New("cookie token is empty")

	// ErrEmptyParamToken can be thrown if authing with parameter in path, the parameter in path is empty
	ErrEmptyParamToken = errors.New("parameter token is empty")

	// ErrInvalidSigningAlgorithm indicates signing algorithm is invalid, needs to be HS256, HS384, HS512, RS256, RS384 or RS512
	ErrInvalidSigningAlgorithm = errors.New("invalid signing algorithm")

	// ErrNoPrivKeyFile indicates that the given private key is unreadable
	ErrNoPrivKeyFile = errors.New("private key file unreadable")

	// ErrNoPubKeyFile indicates that the given public key is unreadable
	ErrNoPubKeyFile = errors.New("public key file unreadable")

	// ErrInvalidPrivKey indicates that the given private key is invalid
	ErrInvalidPrivKey = errors.New("private key invalid")

	// ErrInvalidPubKey indicates the the given public key is invalid
	ErrInvalidPubKey = errors.New("public key invalid")

	// IdentityKey default identity key
	IdentityKey = "identity"

	// ErrMissingRefreshToken indicates the refresh token parameter is missing
	ErrMissingRefreshToken = errors.New("missing refresh_token parameter")

	// ErrInvalidRefreshToken indicates the refresh token is invalid or expired
	ErrInvalidRefreshToken = errors.New("invalid or expired refresh token")

	// ErrRefreshTokenNotFound indicates the refresh token was not found in storage
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
)

// New creates and initializes a new GinJWTMiddleware instance
func New(m *GinJWTMiddleware) (*GinJWTMiddleware, error) {
	if err := m.MiddlewareInit(); err != nil {
		return nil, err
	}

	return m, nil
}

func (mw *GinJWTMiddleware) readKeys() error {
	err := mw.privateKey()
	if err != nil {
		return err
	}

	err = mw.publicKey()
	if err != nil {
		return err
	}
	return nil
}

func (mw *GinJWTMiddleware) privateKey() error {
	var keyData []byte
	var err error
	if mw.PrivKeyFile == "" {
		keyData = mw.PrivKeyBytes
	} else {
		var filecontent []byte
		filecontent, err = os.ReadFile(mw.PrivKeyFile)
		if err != nil {
			// Log detailed error for debugging but don't expose to client
			log.Printf("Failed to read private key file %s: %v", mw.PrivKeyFile, err)
			return ErrNoPrivKeyFile
		}
		keyData = filecontent
	}

	if mw.PrivateKeyPassphrase != "" {
		var key any
		passphrase := []byte(mw.PrivateKeyPassphrase)
		key, err = pkcs8.ParsePKCS8PrivateKey(keyData, passphrase)

		// Clear passphrase from memory immediately after use
		for i := range passphrase {
			passphrase[i] = 0
		}

		if err != nil {
			return ErrInvalidPrivKey
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return ErrInvalidPrivKey
		}
		mw.privKey = rsaKey
		return nil
	}

	var key *rsa.PrivateKey
	key, err = jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPrivKey
	}
	mw.privKey = key
	return nil
}

func (mw *GinJWTMiddleware) publicKey() error {
	var keyData []byte
	if mw.PubKeyFile == "" {
		keyData = mw.PubKeyBytes
	} else {
		filecontent, err := os.ReadFile(mw.PubKeyFile)
		if err != nil {
			// Log detailed error for debugging but don't expose to client
			log.Printf("Failed to read public key file %s: %v", mw.PubKeyFile, err)
			return ErrNoPubKeyFile
		}
		keyData = filecontent
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPubKey
	}
	mw.pubKey = key
	return nil
}

func (mw *GinJWTMiddleware) usingPublicKeyAlgo() bool {
	switch mw.SigningAlgorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}

// MiddlewareInit initializes JWT middleware configuration with default values
func (mw *GinJWTMiddleware) MiddlewareInit() error {
	if mw.TokenLookup == "" {
		mw.TokenLookup = "header:Authorization"
	}

	if mw.SigningAlgorithm == "" {
		mw.SigningAlgorithm = "HS256"
	}

	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}

	if mw.TimeoutFunc == nil {
		mw.TimeoutFunc = func(data any) time.Duration {
			return mw.Timeout
		}
	}

	if mw.TimeFunc == nil {
		mw.TimeFunc = time.Now
	}

	mw.TokenHeadName = strings.TrimSpace(mw.TokenHeadName)
	if mw.TokenHeadName == "" {
		mw.TokenHeadName = "Bearer"
	}

	if mw.Authorizer == nil {
		mw.Authorizer = func(c *gin.Context, data any) bool {
			return true
		}
	}

	if mw.Unauthorized == nil {
		mw.Unauthorized = func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		}
	}

	if mw.LoginResponse == nil {
		mw.LoginResponse = func(c *gin.Context, token *core.Token) {
			response := mw.generateTokenResponse(c, token)
			c.JSON(http.StatusOK, response)
		}
	}

	if mw.LogoutResponse == nil {
		mw.LogoutResponse = func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"code": http.StatusOK,
			})
		}
	}

	if mw.RefreshResponse == nil {
		mw.RefreshResponse = func(c *gin.Context, token *core.Token) {
			response := mw.generateTokenResponse(c, token)
			c.JSON(http.StatusOK, response)
		}
	}

	if mw.IdentityKey == "" {
		mw.IdentityKey = IdentityKey
	}

	if mw.IdentityHandler == nil {
		mw.IdentityHandler = func(c *gin.Context) any {
			claims := ExtractClaims(c)
			return claims[mw.IdentityKey]
		}
	}

	if mw.HTTPStatusMessageFunc == nil {
		mw.HTTPStatusMessageFunc = func(c *gin.Context, e error) string {
			return e.Error()
		}
	}

	if mw.Realm == "" {
		mw.Realm = "gin jwt"
	}

	if mw.CookieMaxAge == 0 {
		mw.CookieMaxAge = mw.Timeout
	}

	if mw.CookieName == "" {
		mw.CookieName = "jwt"
	}

	if mw.RefreshTokenCookieName == "" {
		mw.RefreshTokenCookieName = "refresh_token"
	}

	if mw.ExpField == "" {
		mw.ExpField = "exp"
	}

	// Initialize refresh token settings (RFC 6749 compliant by default)
	if mw.RefreshTokenTimeout == 0 {
		mw.RefreshTokenTimeout = 30 * 24 * time.Hour // 30 days default
	}
	if mw.RefreshTokenLength == 0 {
		mw.RefreshTokenLength = 32 // 256 bits default
	}
	if mw.RefreshTokenStore == nil {
		// Initialize in-memory store first (will be used as fallback)
		mw.inMemoryStore = store.NewInMemoryRefreshTokenStore()

		// Try to initialize Redis store if enabled
		mw.initializeRedisStore()

		// If Redis initialization didn't set a store, use in-memory
		if mw.RefreshTokenStore == nil {
			mw.RefreshTokenStore = mw.inMemoryStore
		}
	}

	// bypass other key settings if KeyFunc is set
	if mw.KeyFunc != nil {
		return nil
	}

	if mw.usingPublicKeyAlgo() {
		return mw.readKeys()
	}

	if mw.Key == nil {
		return ErrMissingSecretKey
	}

	if mw.ParseOptions == nil {
		mw.ParseOptions = make([]jwt.ParserOption, 0, 1)
	}
	mw.ParseOptions = append(mw.ParseOptions, jwt.WithTimeFunc(mw.TimeFunc))

	return nil
}

// MiddlewareFunc makes GinJWTMiddleware implement the Middleware interface.
func (mw *GinJWTMiddleware) MiddlewareFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		mw.middlewareImpl(c)
	}
}

func (mw *GinJWTMiddleware) middlewareImpl(c *gin.Context) {
	claims, err := mw.GetClaimsFromJWT(c)
	if err != nil {
		mw.handleTokenError(c, err)
		return
	}

	// For backwards compatibility since technically exp is not required in the spec but has been in gin-jwt
	if claims["exp"] == nil {
		mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(c, ErrMissingExpField))
		return
	}

	c.Set("JWT_PAYLOAD", claims)
	identity := mw.IdentityHandler(c)

	if identity != nil {
		c.Set(mw.IdentityKey, identity)
	}

	if !mw.Authorizer(c, identity) {
		mw.unauthorized(c, http.StatusForbidden, mw.HTTPStatusMessageFunc(c, ErrForbidden))
		return
	}

	c.Next()
}

// GetClaimsFromJWT get claims from JWT token
func (mw *GinJWTMiddleware) GetClaimsFromJWT(c *gin.Context) (jwt.MapClaims, error) {
	token, err := mw.ParseToken(c)
	if err != nil {
		return nil, err
	}

	if mw.SendAuthorization {
		if v, ok := c.Get("JWT_TOKEN"); ok {
			if tokenStr, ok := v.(string); ok {
				c.Header("Authorization", mw.TokenHeadName+" "+tokenStr)
			}
		}
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims type")
	}

	// Return the claims directly without unnecessary copying
	return mapClaims, nil
}

// LoginHandler can be used by clients to get a jwt token.
// Payload needs to be json in the form of {"username": "USERNAME", "password": "PASSWORD"}.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *GinJWTMiddleware) LoginHandler(c *gin.Context) {
	if mw.Authenticator == nil {
		mw.unauthorized(
			c,
			http.StatusInternalServerError,
			mw.HTTPStatusMessageFunc(c, ErrMissingAuthenticatorFunc),
		)
		return
	}

	data, err := mw.Authenticator(c)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(c, err))
		return
	}

	// Generate complete token pair
	tokenPair, err := mw.TokenGenerator(c.Request.Context(), data)
	if err != nil {
		mw.unauthorized(
			c,
			http.StatusInternalServerError,
			mw.HTTPStatusMessageFunc(c, ErrFailedTokenCreation),
		)
		return
	}

	// Set cookies
	mw.SetCookie(c, tokenPair.AccessToken)
	mw.SetRefreshTokenCookie(c, tokenPair.RefreshToken)

	mw.LoginResponse(c, tokenPair)
}

func (mw *GinJWTMiddleware) extractRefreshToken(c *gin.Context) string {
	// Try to get refresh token from cookie first (most common for browser-based apps)
	token, _ := c.Cookie(mw.RefreshTokenCookieName)
	if token != "" {
		return token
	}

	// SECURITY: Query parameters are NOT supported for refresh tokens to prevent
	// token leakage through server logs, proxy logs, browser history, and Referer headers.
	// Only secure methods are supported: httpOnly cookies, request body (form/JSON).

	// Check Content-Type to determine how to parse body
	// This prevents consuming the body twice
	contentType := c.ContentType()

	if strings.Contains(contentType, "application/x-www-form-urlencoded") ||
		strings.Contains(contentType, "multipart/form-data") {
		// Try POST form
		token = c.PostForm("refresh_token")
		if token != "" {
			return token
		}
	} else if strings.Contains(contentType, "application/json") {
		// Try JSON body
		var reqBody struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := c.ShouldBindJSON(&reqBody); err == nil {
			token = reqBody.RefreshToken
		}
	}

	return token
}

// LogoutHandler can be used by clients to remove the jwt cookie and revoke refresh token
func (mw *GinJWTMiddleware) LogoutHandler(c *gin.Context) {
	// Extract JWT claims to make them available in LogoutResponse
	// This allows developers to access user information during logout
	claims, err := mw.GetClaimsFromJWT(c)
	if err == nil {
		c.Set("JWT_PAYLOAD", claims)
		identity := mw.IdentityHandler(c)
		if identity != nil {
			c.Set(mw.IdentityKey, identity)
		}
	}

	// Handle refresh token revocation (RFC 6749 compliant)
	refreshToken := mw.extractRefreshToken(c)
	if refreshToken != "" {
		if err := mw.revokeRefreshToken(c.Request.Context(), refreshToken); err != nil {
			log.Printf("Failed to revoke refresh token on logout: %v", err)
		}
	}

	// delete auth cookies
	if mw.SendCookie {
		if mw.CookieSameSite != 0 {
			c.SetSameSite(mw.CookieSameSite)
		}

		// Delete access token cookie
		c.SetCookie(
			mw.CookieName,
			"",
			-1,
			"/",
			mw.CookieDomain,
			mw.SecureCookie,
			mw.CookieHTTPOnly,
		)

		// Delete refresh token cookie
		c.SetCookie(
			mw.RefreshTokenCookieName,
			"",
			-1,
			"/",
			mw.CookieDomain,
			true, // Must match the secure flag used when setting the cookie
			true,
		)
	}

	mw.LogoutResponse(c)
}

func (mw *GinJWTMiddleware) signedString(token *jwt.Token) (string, error) {
	var tokenString string
	var err error
	if mw.usingPublicKeyAlgo() {
		tokenString, err = token.SignedString(mw.privKey)
	} else {
		tokenString, err = token.SignedString(mw.Key)
	}
	return tokenString, err
}

// generateRefreshToken creates a cryptographically secure random refresh token
func (mw *GinJWTMiddleware) generateRefreshToken() (string, error) {
	bytes := make([]byte, mw.RefreshTokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// storeRefreshToken stores a refresh token with user data
func (mw *GinJWTMiddleware) storeRefreshToken(
	ctx context.Context,
	token string,
	userData any,
) error {
	expiry := mw.TimeFunc().Add(mw.RefreshTokenTimeout)
	return mw.RefreshTokenStore.Set(ctx, token, userData, expiry)
}

// validateRefreshToken validates a refresh token and returns associated user data
func (mw *GinJWTMiddleware) validateRefreshToken(ctx context.Context, token string) (any, error) {
	userData, err := mw.RefreshTokenStore.Get(ctx, token)
	if err != nil {
		if err == core.ErrRefreshTokenNotFound {
			return nil, ErrInvalidRefreshToken
		}
		return nil, err
	}
	return userData, nil
}

// revokeRefreshToken removes a refresh token from storage
func (mw *GinJWTMiddleware) revokeRefreshToken(ctx context.Context, token string) error {
	return mw.RefreshTokenStore.Delete(ctx, token)
}

// RefreshHandler can be used to refresh a token using RFC 6749 compliant refresh tokens.
// This handler expects a refresh_token parameter and returns a new access token and refresh token.
// Reply will be of the form {"access_token": "TOKEN", "refresh_token": "REFRESH_TOKEN"}.
func (mw *GinJWTMiddleware) RefreshHandler(c *gin.Context) {
	// Extract refresh token from request
	refreshToken := mw.extractRefreshToken(c)
	if refreshToken == "" {
		mw.unauthorized(
			c,
			http.StatusBadRequest,
			mw.HTTPStatusMessageFunc(c, ErrMissingRefreshToken),
		)
		return
	}

	// Validate refresh token
	userData, err := mw.validateRefreshToken(c.Request.Context(), refreshToken)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(c, err))
		return
	}

	// Generate new token pair and revoke old refresh token
	tokenPair, err := mw.TokenGeneratorWithRevocation(c.Request.Context(), userData, refreshToken)
	if err != nil {
		mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(c, err))
		return
	}

	// Set cookies
	mw.SetCookie(c, tokenPair.AccessToken)
	mw.SetRefreshTokenCookie(c, tokenPair.RefreshToken)

	mw.RefreshResponse(c, tokenPair)
}

// CheckIfTokenExpire check if token expire
func (mw *GinJWTMiddleware) CheckIfTokenExpire(c *gin.Context) (jwt.MapClaims, error) {
	token, err := mw.ParseToken(c)
	if err != nil {
		// If we receive an error, and the error is anything other than a single
		// ValidationErrorExpired, we want to return the error.
		// If the error is just ValidationErrorExpired, we want to continue, as we can still
		// refresh the token if it's within the MaxRefresh time.
		// (see https://github.com/appleboy/gin-jwt/issues/176)
		if !errors.Is(err, jwt.ErrTokenExpired) {
			return nil, err
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims type")
	}

	origIatValue, exists := claims["orig_iat"]
	if !exists {
		return nil, errors.New("missing orig_iat claim")
	}

	origIatFloat, ok := origIatValue.(float64)
	if !ok {
		return nil, errors.New("invalid orig_iat format")
	}

	origIat := int64(origIatFloat)
	if origIat < mw.TimeFunc().Add(-mw.MaxRefresh).Unix() {
		return nil, ErrExpiredToken
	}

	return claims, nil
}

// generateAccessToken method that clients can use to get a jwt token.
func (mw *GinJWTMiddleware) generateAccessToken(data any) (string, time.Time, error) {
	// 1. Validate signing algorithm
	signingMethod := jwt.GetSigningMethod(mw.SigningAlgorithm)
	if signingMethod == nil {
		return "", time.Time{}, ErrInvalidSigningAlgorithm
	}

	token := jwt.New(signingMethod)
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", time.Time{}, ErrFailedTokenCreation
	}

	// 2. Define framework-controlled claims that PayloadFunc cannot overwrite
	// Only claims that the framework calculates/manages internally are reserved.
	// Standard JWT claims (sub, iss, aud, nbf, iat, jti) are allowed to be set by users
	// via PayloadFunc to comply with RFC 7519 best practices.
	frameworkClaims := map[string]bool{
		"exp":      true, // Framework calculates expiration time
		"orig_iat": true, // Framework uses this for refresh mechanism
	}

	// 3. Safely add custom payload, avoiding framework-controlled field overwrites
	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(data) {
			if !frameworkClaims[key] {
				claims[key] = value
			}
		}
	}

	// 4. Calculate expiration time using original data instead of claims
	expire := mw.TimeFunc().Add(mw.TimeoutFunc(data))

	// 5. Set required system claims
	now := mw.TimeFunc()
	claims[mw.ExpField] = expire.Unix()
	claims["orig_iat"] = now.Unix()

	// 6. Sign the token
	tokenString, err := mw.signedString(token)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expire, nil
}

// TokenGenerator generates a complete token pair (access + refresh) with RFC 6749 compliance
func (mw *GinJWTMiddleware) TokenGenerator(ctx context.Context, data any) (*core.Token, error) {
	// Generate access token
	accessToken, expire, err := mw.generateAccessToken(data)
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken, err := mw.generateRefreshToken()
	if err != nil {
		return nil, err
	}

	// Store refresh token
	if err := mw.storeRefreshToken(ctx, refreshToken, data); err != nil {
		return nil, err
	}

	now := mw.TimeFunc()
	return &core.Token{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		ExpiresAt:    expire.Unix(),
		CreatedAt:    now.Unix(),
	}, nil
}

// TokenGeneratorWithRevocation generates a new token pair and revokes the old refresh token
func (mw *GinJWTMiddleware) TokenGeneratorWithRevocation(
	ctx context.Context,
	data any,
	oldRefreshToken string,
) (*core.Token, error) {
	// Generate new token pair
	tokenPair, err := mw.TokenGenerator(ctx, data)
	if err != nil {
		return nil, err
	}

	// Revoke old refresh token, ignore if token already doesn't exist
	if err := mw.revokeRefreshToken(ctx, oldRefreshToken); err != nil &&
		!errors.Is(err, core.ErrRefreshTokenNotFound) {
		return nil, err
	}

	return tokenPair, nil
}

func (mw *GinJWTMiddleware) jwtFromHeader(c *gin.Context, key string) (string, error) {
	authHeader := c.Request.Header.Get(key)

	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != mw.TokenHeadName {
		return "", ErrInvalidAuthHeader
	}

	return parts[1], nil
}

func (mw *GinJWTMiddleware) jwtFromQuery(c *gin.Context, key string) (string, error) {
	token := c.Query(key)

	if token == "" {
		return "", ErrEmptyQueryToken
	}

	return token, nil
}

func (mw *GinJWTMiddleware) jwtFromCookie(c *gin.Context, key string) (string, error) {
	cookie, _ := c.Cookie(key)

	if cookie == "" {
		return "", ErrEmptyCookieToken
	}

	return cookie, nil
}

func (mw *GinJWTMiddleware) jwtFromParam(c *gin.Context, key string) (string, error) {
	token := c.Param(key)

	if token == "" {
		return "", ErrEmptyParamToken
	}

	return token, nil
}

func (mw *GinJWTMiddleware) jwtFromForm(c *gin.Context, key string) (string, error) {
	token := c.PostForm(key)

	if token == "" {
		return "", ErrEmptyParamToken
	}

	return token, nil
}

// ParseToken parse jwt token from gin context
func (mw *GinJWTMiddleware) ParseToken(c *gin.Context) (*jwt.Token, error) {
	var token string
	var err error

	methods := strings.Split(mw.TokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "header":
			token, err = mw.jwtFromHeader(c, v)
		case "query":
			token, err = mw.jwtFromQuery(c, v)
		case "cookie":
			token, err = mw.jwtFromCookie(c, v)
		case "param":
			token, err = mw.jwtFromParam(c, v)
		case "form":
			token, err = mw.jwtFromForm(c, v)
		}
	}

	if err != nil {
		return nil, err
	}

	if mw.KeyFunc != nil {
		return jwt.Parse(token, mw.KeyFunc, mw.ParseOptions...)
	}

	return jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if mw.usingPublicKeyAlgo() {
			return mw.pubKey, nil
		}

		// save token string if valid
		c.Set("JWT_TOKEN", token)

		return mw.Key, nil
	}, mw.ParseOptions...)
}

// ParseTokenString parse jwt token string
func (mw *GinJWTMiddleware) ParseTokenString(token string) (*jwt.Token, error) {
	if mw.KeyFunc != nil {
		return jwt.Parse(token, mw.KeyFunc, mw.ParseOptions...)
	}

	return jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if mw.usingPublicKeyAlgo() {
			return mw.pubKey, nil
		}

		return mw.Key, nil
	}, mw.ParseOptions...)
}

// unauthorized handles unauthorized requests by setting the WWW-Authenticate header
// and calling the user-defined Unauthorized callback.
//
// According to RFC 6750 (OAuth 2.0 Bearer Token Usage) and RFC 7235 (HTTP Authentication),
// a 401 Unauthorized response must include a WWW-Authenticate header with the Bearer scheme.
// This ensures compatibility with standard HTTP clients and authentication frameworks.
//
// See:
//   - https://tools.ietf.org/html/rfc6750
//   - https://tools.ietf.org/html/rfc7235
//   - https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401
func (mw *GinJWTMiddleware) unauthorized(c *gin.Context, code int, message string) {
	c.Header("WWW-Authenticate", "Bearer realm=\""+mw.Realm+"\"")
	if !mw.DisabledAbort {
		c.Abort()
	}

	mw.Unauthorized(c, code, message)
}

// ExtractClaims help to extract the JWT claims
func ExtractClaims(c *gin.Context) jwt.MapClaims {
	claims, exists := c.Get("JWT_PAYLOAD")
	if !exists {
		return make(jwt.MapClaims)
	}

	mapClaims, ok := claims.(jwt.MapClaims)
	if !ok {
		return make(jwt.MapClaims)
	}

	return mapClaims
}

// ExtractClaimsFromToken help to extract the JWT claims from token
func ExtractClaimsFromToken(token *jwt.Token) jwt.MapClaims {
	if token == nil {
		return make(jwt.MapClaims)
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return make(jwt.MapClaims)
	}

	// Return the claims directly without unnecessary copying
	return mapClaims
}

// GetToken help to get the JWT token string
func GetToken(c *gin.Context) string {
	token, exists := c.Get("JWT_TOKEN")
	if !exists {
		return ""
	}

	tokenStr, ok := token.(string)
	if !ok {
		return ""
	}

	return tokenStr
}

// SetCookie help to set the token in the cookie
func (mw *GinJWTMiddleware) SetCookie(c *gin.Context, token string) {
	// set cookie
	if mw.SendCookie {
		expireCookie := mw.TimeFunc().Add(mw.CookieMaxAge)
		maxage := int(expireCookie.Unix() - mw.TimeFunc().Unix())

		if mw.CookieSameSite != 0 {
			c.SetSameSite(mw.CookieSameSite)
		}

		c.SetCookie(
			mw.CookieName,
			token,
			maxage,
			"/",
			mw.CookieDomain,
			mw.SecureCookie,
			mw.CookieHTTPOnly,
		)
	}
}

// SetRefreshTokenCookie help to set the refresh token in the cookie
func (mw *GinJWTMiddleware) SetRefreshTokenCookie(c *gin.Context, refreshToken string) {
	if mw.SendCookie {
		expireCookie := mw.TimeFunc().Add(mw.RefreshTokenTimeout)
		maxage := int(expireCookie.Unix() - mw.TimeFunc().Unix())

		if mw.CookieSameSite != 0 {
			c.SetSameSite(mw.CookieSameSite)
		}

		c.SetCookie(
			mw.RefreshTokenCookieName,
			refreshToken,
			maxage,
			"/",
			mw.CookieDomain,
			true, // Always secure for refresh tokens (HTTPS only)
			true, // Always httpOnly for security
		)
	}
}

// handleTokenError handles different types of JWT token validation errors
func (mw *GinJWTMiddleware) handleTokenError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(c, ErrExpiredToken))
	case errors.Is(err, jwt.ErrInvalidType) && strings.Contains(err.Error(), "exp is invalid"):
		mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(c, ErrWrongFormatOfExp))
	case errors.Is(err, jwt.ErrTokenRequiredClaimMissing) && strings.Contains(err.Error(), "exp claim is required"):
		mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(c, ErrMissingExpField))
	default:
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(c, err))
	}
}

// generateTokenResponse creates a RFC 6749 compliant token response with refresh token
func (mw *GinJWTMiddleware) generateTokenResponse(_ *gin.Context, token *core.Token) gin.H {
	response := gin.H{
		"access_token": token.AccessToken,
		"token_type":   token.TokenType,
		"expires_in":   token.ExpiresIn(),
	}

	// Include refresh token if present
	if token.RefreshToken != "" {
		response["refresh_token"] = token.RefreshToken
	}

	return response
}

// ClearSensitiveData clears sensitive data from memory
func (mw *GinJWTMiddleware) ClearSensitiveData() {
	// Clear symmetric key
	if mw.Key != nil {
		for i := range mw.Key {
			mw.Key[i] = 0
		}
		mw.Key = nil
	}

	// Clear private key bytes
	if mw.PrivKeyBytes != nil {
		for i := range mw.PrivKeyBytes {
			mw.PrivKeyBytes[i] = 0
		}
		mw.PrivKeyBytes = nil
	}

	// Clear public key bytes
	if mw.PubKeyBytes != nil {
		for i := range mw.PubKeyBytes {
			mw.PubKeyBytes[i] = 0
		}
		mw.PubKeyBytes = nil
	}

	// Clear passphrase
	if len(mw.PrivateKeyPassphrase) > 0 {
		// Convert to []byte to clear, then back to string
		passBytes := []byte(mw.PrivateKeyPassphrase)
		for i := range passBytes {
			passBytes[i] = 0
		}
		mw.PrivateKeyPassphrase = ""
	}

	// Note: RSA keys (mw.privKey, mw.pubKey) are harder to clear completely
	// due to Go's garbage collector, but setting to nil helps
	mw.privKey = nil
	mw.pubKey = nil

	// Clear refresh token store if using in-memory store
	if mw.inMemoryStore != nil {
		mw.inMemoryStore.Clear()
	}
}
