package jwt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/appleboy/gofight/v2"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

// validAuthenticator is a properly functioning authenticator for cookie tests
var validAuthenticator = func(c *gin.Context) (any, error) {
	var loginVals Login
	if err := c.ShouldBind(&loginVals); err != nil {
		return "", ErrMissingLoginValues
	}
	if loginVals.Username == testAdmin && loginVals.Password == testPassword {
		return loginVals.Username, nil
	}
	return "", ErrFailedAuthentication
}

func TestSetRefreshTokenCookie(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	mw, _ := New(&GinJWTMiddleware{
		Realm:                  "test zone",
		Key:                    key,
		Timeout:                time.Hour,
		RefreshTokenTimeout:    24 * time.Hour,
		Authenticator:          validAuthenticator,
		SendCookie:             true,
		RefreshTokenCookieName: "refresh_token",
		CookieDomain:           "example.com",
		SecureCookie:           false,
		CookieHTTPOnly:         true,
		TimeFunc:               time.Now,
	})

	refreshToken := "test-refresh-token-12345"

	mw.SetRefreshTokenCookie(c, refreshToken)

	cookies := w.Result().Cookies()

	// Should have one refresh token cookie
	assert.Len(t, cookies, 1)
	assert.Equal(t, "refresh_token", cookies[0].Name)
	assert.Equal(t, refreshToken, cookies[0].Value)
	assert.Equal(t, "example.com", cookies[0].Domain)
	assert.True(t, cookies[0].HttpOnly)
	assert.True(t, cookies[0].Secure) // Refresh token cookies are always secure (HTTPS only)
	assert.Equal(t, "/", cookies[0].Path)
	assert.True(t, cookies[0].MaxAge > 0)
}

func TestSetRefreshTokenCookieDisabled(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	mw, _ := New(&GinJWTMiddleware{
		Realm:               "test zone",
		Key:                 key,
		Timeout:             time.Hour,
		RefreshTokenTimeout: 24 * time.Hour,
		Authenticator:       validAuthenticator,
		SendCookie:          false, // Cookie disabled
		TimeFunc:            time.Now,
	})

	refreshToken := "test-refresh-token-12345"

	mw.SetRefreshTokenCookie(c, refreshToken)

	cookies := w.Result().Cookies()

	// Should not set any cookies when SendCookie is false
	assert.Len(t, cookies, 0)
}

func TestExtractRefreshTokenFromCookie(t *testing.T) {
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:                  "test zone",
		Key:                    key,
		Timeout:                time.Hour,
		MaxRefresh:             time.Hour * 24,
		Authenticator:          validAuthenticator,
		SendCookie:             true,
		RefreshTokenCookieName: "refresh_token",
	})

	handler := ginHandler(authMiddleware)

	// Create a test context with refresh token cookie
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: "test-refresh-token-from-cookie",
	})

	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Test extraction
	token := authMiddleware.extractRefreshToken(c)
	assert.Equal(t, "test-refresh-token-from-cookie", token)

	_ = handler
}

func TestExtractRefreshTokenPriority(t *testing.T) {
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:                  "test zone",
		Key:                    key,
		Timeout:                time.Hour,
		MaxRefresh:             time.Hour * 24,
		Authenticator:          validAuthenticator,
		SendCookie:             true,
		RefreshTokenCookieName: "refresh_token",
	})

	// Test: Cookie has highest priority
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"/test?refresh_token=from-query",
		nil,
	)
	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: "from-cookie",
	})
	req.Form = map[string][]string{
		"refresh_token": {"from-form"},
	}

	c, _ := gin.CreateTestContext(w)
	c.Request = req

	token := authMiddleware.extractRefreshToken(c)
	assert.Equal(t, "from-cookie", token, "Cookie should have highest priority")
}

func TestLoginHandlerSetsRefreshTokenCookie(t *testing.T) {
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:                  "test zone",
		Key:                    key,
		Timeout:                time.Hour,
		RefreshTokenTimeout:    24 * time.Hour,
		MaxRefresh:             time.Hour * 24,
		Authenticator:          validAuthenticator,
		SendCookie:             true,
		CookieName:             "jwt",
		RefreshTokenCookieName: "refresh_token",
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.POST("/login").
		SetJSON(gofight.D{
			"username": testAdmin,
			"password": testPassword,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)

			// Check that both cookies are set
			setCookieHeaders := (*httptest.ResponseRecorder)(r).Result().Header.Values("Set-Cookie")
			assert.True(t, len(setCookieHeaders) >= 2, "Should set at least 2 cookies")

			hasJWTCookie := false
			hasRefreshTokenCookie := false

			for _, cookie := range setCookieHeaders {
				if contains(cookie, "jwt=") {
					hasJWTCookie = true
				}
				if contains(cookie, "refresh_token=") {
					hasRefreshTokenCookie = true
				}
			}

			assert.True(t, hasJWTCookie, "Should set JWT cookie")
			assert.True(t, hasRefreshTokenCookie, "Should set refresh token cookie")

			// Verify response contains tokens
			accessToken := gjson.Get(r.Body.String(), "access_token")
			refreshToken := gjson.Get(r.Body.String(), "refresh_token")
			assert.True(t, accessToken.Exists())
			assert.True(t, refreshToken.Exists())
		})
}

func TestRefreshHandlerWithCookie(t *testing.T) {
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:                  "test zone",
		Key:                    key,
		Timeout:                time.Hour,
		RefreshTokenTimeout:    24 * time.Hour,
		MaxRefresh:             time.Hour * 24,
		Authenticator:          validAuthenticator,
		SendCookie:             true,
		CookieName:             "jwt",
		RefreshTokenCookieName: "refresh_token",
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	// First, login to get refresh token
	var refreshToken string
	r.POST("/login").
		SetJSON(gofight.D{
			"username": testAdmin,
			"password": testPassword,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
			refreshToken = gjson.Get(r.Body.String(), "refresh_token").String()
			assert.NotEmpty(t, refreshToken)
		})

	// Test refresh with cookie (automatic)
	r.POST("/refresh").
		SetCookie(gofight.H{
			"refresh_token": refreshToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)

			// Check that new tokens are returned
			newAccessToken := gjson.Get(r.Body.String(), "access_token")
			newRefreshToken := gjson.Get(r.Body.String(), "refresh_token")
			assert.True(t, newAccessToken.Exists())
			assert.True(t, newRefreshToken.Exists())
			assert.NotEqual(
				t,
				refreshToken,
				newRefreshToken.String(),
				"Refresh token should be rotated",
			)

			// Check that new cookies are set
			setCookieHeaders := (*httptest.ResponseRecorder)(r).Result().Header.Values("Set-Cookie")
			assert.True(t, len(setCookieHeaders) >= 2, "Should set new cookies")
		})
}

func TestRefreshHandlerWithoutCookie(t *testing.T) {
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:               "test zone",
		Key:                 key,
		Timeout:             time.Hour,
		RefreshTokenTimeout: 24 * time.Hour,
		MaxRefresh:          time.Hour * 24,
		Authenticator:       validAuthenticator,
		SendCookie:          true,
		CookieName:          "jwt",
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	// First, login to get refresh token
	var refreshToken string
	r.POST("/login").
		SetJSON(gofight.D{
			"username": testAdmin,
			"password": testPassword,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
			refreshToken = gjson.Get(r.Body.String(), "refresh_token").String()
			assert.NotEmpty(t, refreshToken)
		})

	// Test refresh with form data (manual)
	r.POST("/refresh").
		SetForm(gofight.H{
			"refresh_token": refreshToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)

			newAccessToken := gjson.Get(r.Body.String(), "access_token")
			assert.True(t, newAccessToken.Exists())
		})

	// Test refresh with JSON body
	var refreshToken2 string
	r.POST("/login").
		SetJSON(gofight.D{
			"username": testAdmin,
			"password": testPassword,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			refreshToken2 = gjson.Get(r.Body.String(), "refresh_token").String()
		})

	r.POST("/refresh").
		SetJSON(gofight.D{
			"refresh_token": refreshToken2,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)

			newAccessToken := gjson.Get(r.Body.String(), "access_token")
			assert.True(t, newAccessToken.Exists())
		})
}

func TestLogoutHandlerClearsRefreshTokenCookie(t *testing.T) {
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:                  "test zone",
		Key:                    key,
		Timeout:                time.Hour,
		RefreshTokenTimeout:    24 * time.Hour,
		MaxRefresh:             time.Hour * 24,
		Authenticator:          validAuthenticator,
		SendCookie:             true,
		CookieName:             "jwt",
		RefreshTokenCookieName: "refresh_token",
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	// First, login to get tokens
	var accessToken, refreshToken string
	r.POST("/login").
		SetJSON(gofight.D{
			"username": testAdmin,
			"password": testPassword,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
			accessToken = gjson.Get(r.Body.String(), "access_token").String()
			refreshToken = gjson.Get(r.Body.String(), "refresh_token").String()
			assert.NotEmpty(t, accessToken)
			assert.NotEmpty(t, refreshToken)
		})

	// Logout with cookies
	r.POST("/logout").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + accessToken,
		}).
		SetCookie(gofight.H{
			"jwt":           accessToken,
			"refresh_token": refreshToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)

			// Check that both cookies are cleared (MaxAge=-1)
			setCookieHeaders := (*httptest.ResponseRecorder)(r).Result().Header.Values("Set-Cookie")
			assert.True(t, len(setCookieHeaders) >= 2, "Should clear cookies")

			hasJWTClear := false
			hasRefreshTokenClear := false

			for _, cookie := range setCookieHeaders {
				if contains(cookie, "jwt=") && contains(cookie, "Max-Age=0") {
					hasJWTClear = true
				}
				if contains(cookie, "refresh_token=") && contains(cookie, "Max-Age=0") {
					hasRefreshTokenClear = true
				}
			}

			assert.True(t, hasJWTClear, "Should clear JWT cookie")
			assert.True(t, hasRefreshTokenClear, "Should clear refresh token cookie")
		})
}

func TestRefreshTokenRevocationOnLogout(t *testing.T) {
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:               "test zone",
		Key:                 key,
		Timeout:             time.Hour,
		RefreshTokenTimeout: 24 * time.Hour,
		MaxRefresh:          time.Hour * 24,
		Authenticator:       validAuthenticator,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	// Login to get tokens
	var accessToken, refreshToken string
	r.POST("/login").
		SetJSON(gofight.D{
			"username": testAdmin,
			"password": testPassword,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
			accessToken = gjson.Get(r.Body.String(), "access_token").String()
			refreshToken = gjson.Get(r.Body.String(), "refresh_token").String()
		})

	// Logout to revoke refresh token
	r.POST("/logout").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + accessToken,
		}).
		SetForm(gofight.H{
			"refresh_token": refreshToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})

	// Try to use revoked refresh token
	r.POST("/refresh").
		SetForm(gofight.H{
			"refresh_token": refreshToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})
}

func TestRefreshTokenCookieName(t *testing.T) {
	customCookieName := "my_refresh_token"

	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:                  "test zone",
		Key:                    key,
		Timeout:                time.Hour,
		RefreshTokenTimeout:    24 * time.Hour,
		MaxRefresh:             time.Hour * 24,
		Authenticator:          validAuthenticator,
		SendCookie:             true,
		RefreshTokenCookieName: customCookieName,
	})

	// Check default is set correctly during init
	assert.Equal(t, customCookieName, authMiddleware.RefreshTokenCookieName)

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	// Login and check custom cookie name
	r.POST("/login").
		SetJSON(gofight.D{
			"username": testAdmin,
			"password": testPassword,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)

			setCookieHeaders := (*httptest.ResponseRecorder)(r).Result().Header.Values("Set-Cookie")
			hasCustomCookie := false

			for _, cookie := range setCookieHeaders {
				if contains(cookie, customCookieName+"=") {
					hasCustomCookie = true
					break
				}
			}

			assert.True(t, hasCustomCookie, "Should use custom refresh token cookie name")
		})
}

func TestRefreshTokenCookieDefault(t *testing.T) {
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:               "test zone",
		Key:                 key,
		Timeout:             time.Hour,
		RefreshTokenTimeout: 24 * time.Hour,
		MaxRefresh:          time.Hour * 24,
		Authenticator:       validAuthenticator,
		SendCookie:          true,
		// Don't set RefreshTokenCookieName to test default
	})

	// Check default is set during init
	assert.Equal(t, "refresh_token", authMiddleware.RefreshTokenCookieName)
}

func TestTokenGeneratorSetsRefreshToken(t *testing.T) {
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:               "test zone",
		Key:                 key,
		Timeout:             time.Hour,
		RefreshTokenTimeout: 24 * time.Hour,
		Authenticator:       validAuthenticator,
	})

	ctx := context.Background()
	userData := testAdmin

	tokenPair, err := authMiddleware.TokenGenerator(ctx, userData)

	assert.NoError(t, err)
	assert.NotNil(t, tokenPair)
	assert.NotEmpty(t, tokenPair.AccessToken)
	assert.NotEmpty(t, tokenPair.RefreshToken)
	assert.Equal(t, "Bearer", tokenPair.TokenType)
	assert.True(t, tokenPair.ExpiresAt > 0)
	assert.True(t, tokenPair.CreatedAt > 0)
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
