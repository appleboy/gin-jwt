package jwt

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/appleboy/gin-jwt/v3/core"
	"github.com/appleboy/gofight/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

// Login form structure.
type Login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

const (
	testAdmin      = "admin"
	testJWT        = "jwt"
	testUser       = "test"
	testPassword   = testAdmin
	testUserPasswd = testUser
)

var (
	key                  = []byte("secret key")
	defaultAuthenticator = func(c *gin.Context) (any, error) {
		var loginVals Login
		userID := loginVals.Username
		password := loginVals.Password

		if userID == testAdmin && password == testPassword {
			return userID, nil
		}

		return userID, ErrFailedAuthentication
	}
)

func makeTokenString(signingAlgorithm, username string) string {
	if signingAlgorithm == "" {
		signingAlgorithm = "HS256"
	}

	token := jwt.New(jwt.GetSigningMethod(signingAlgorithm))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = username
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["orig_iat"] = time.Now().Unix()
	var tokenString string
	if signingAlgorithm == "RS256" {
		keyData, _ := os.ReadFile("testdata/jwtRS256.key")
		signKey, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)
		tokenString, _ = token.SignedString(signKey)
	} else {
		tokenString, _ = token.SignedString(key)
	}

	return tokenString
}

func keyFunc(token *jwt.Token) (any, error) {
	cert, err := os.ReadFile("testdata/jwtRS256.key.pub")
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPublicKeyFromPEM(cert)
}

func TestMissingKey(t *testing.T) {
	_, err := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})

	assert.Error(t, err)
	assert.Equal(t, ErrMissingSecretKey, err)
}

func TestMissingPrivKey(t *testing.T) {
	_, err := New(&GinJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "nonexisting",
	})

	assert.Error(t, err)
	assert.Equal(t, ErrNoPrivKeyFile, err)
}

func TestMissingPubKey(t *testing.T) {
	_, err := New(&GinJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyFile:       "nonexisting",
	})

	assert.Error(t, err)
	assert.Equal(t, ErrNoPubKeyFile, err)
}

func TestInvalidPrivKey(t *testing.T) {
	_, err := New(&GinJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/invalidprivkey.key",
		PubKeyFile:       "testdata/jwtRS256.key.pub",
	})

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPrivKey, err)
}

func TestInvalidPrivKeyBytes(t *testing.T) {
	_, err := New(&GinJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyBytes:     []byte("Invalid_Private_Key"),
		PubKeyFile:       "testdata/jwtRS256.key.pub",
	})

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPrivKey, err)
}

func TestInvalidPubKey(t *testing.T) {
	_, err := New(&GinJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyFile:       "testdata/invalidpubkey.key",
	})

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPubKey, err)
}

func TestInvalidPubKeyBytes(t *testing.T) {
	_, err := New(&GinJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyBytes:      []byte("Invalid_Private_Key"),
	})

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPubKey, err)
}

func TestMissingTimeOut(t *testing.T) {
	authMiddleware, err := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Authenticator: defaultAuthenticator,
	})

	assert.NoError(t, err)
	assert.Equal(t, time.Hour, authMiddleware.Timeout)
}

func TestMissingTokenLookup(t *testing.T) {
	authMiddleware, err := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Authenticator: defaultAuthenticator,
	})

	assert.NoError(t, err)
	assert.Equal(t, "header:Authorization", authMiddleware.TokenLookup)
}

func helloHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"text":  "Hello World.",
		"token": GetToken(c),
	})
}

// getRefreshTokenFromLogin performs a login and returns the refresh token from the response
func getRefreshTokenFromLogin(handler *gin.Engine) string {
	r := gofight.New()
	var refreshToken string

	r.POST("/login").
		SetJSON(gofight.D{
			"username": testAdmin,
			"password": testAdmin,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			if r.Code == http.StatusOK {
				refreshToken = gjson.Get(r.Body.String(), "refresh_token").String()
			}
		})

	return refreshToken
}

func ginHandler(auth *GinJWTMiddleware) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	r.POST("/login", auth.LoginHandler)
	r.POST("/logout", auth.LogoutHandler)
	r.POST("/refresh", auth.RefreshHandler)

	group := r.Group("/auth")
	// Refresh time can be longer than token timeout
	group.POST("/refresh_token", auth.RefreshHandler)
	group.Use(auth.MiddlewareFunc())
	{
		group.GET("/hello", helloHandler)
	}

	// Add back the param-based endpoint for testing
	r.GET("/g/:token/hello", auth.MiddlewareFunc(), helloHandler)

	return r
}

func TestMissingAuthenticatorForLoginHandler(t *testing.T) {
	authMiddleware, err := New(&GinJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
	})

	assert.NoError(t, err)

	handler := ginHandler(authMiddleware)
	r := gofight.New()

	r.POST("/login").
		SetJSON(gofight.D{
			"username": testAdmin,
			"password": testAdmin,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			message := gjson.Get(r.Body.String(), "message")

			assert.Equal(t, ErrMissingAuthenticatorFunc.Error(), message.String())
			assert.Equal(t, http.StatusInternalServerError, r.Code)
		})
}

func TestLoginHandler(t *testing.T) {
	// the middleware to test
	cookieName := testJWT
	cookieDomain := "example.com"
	authMiddleware, err := New(&GinJWTMiddleware{
		Realm: "test zone",
		Key:   key,
		PayloadFunc: func(data any) jwt.MapClaims {
			// Set custom claim, to be checked in Authorizer method
			return jwt.MapClaims{"testkey": "testval", "exp": 0}
		},
		Authenticator: func(c *gin.Context) (any, error) {
			var loginVals Login
			if binderr := c.ShouldBind(&loginVals); binderr != nil {
				return "", ErrMissingLoginValues
			}
			userID := loginVals.Username
			password := loginVals.Password
			if userID == testAdmin && password == testPassword {
				return userID, nil
			}
			return "", ErrFailedAuthentication
		},
		Authorizer: func(c *gin.Context, user any) bool {
			return true
		},
		LoginResponse: func(c *gin.Context, token *core.Token) {
			cookie, err := c.Cookie(testJWT)
			if err != nil {
				log.Println(err)
			}

			expire := time.Unix(token.ExpiresAt, 0)
			c.JSON(http.StatusOK, gin.H{
				"code":    http.StatusOK,
				"token":   token.AccessToken,
				"expire":  expire.Format(time.RFC3339),
				"message": "login successfully",
				"cookie":  cookie,
			})
		},
		SendCookie:   true,
		CookieName:   cookieName,
		CookieDomain: cookieDomain,
		TimeFunc:     func() time.Time { return time.Now().Add(time.Duration(5) * time.Minute) },
	})

	assert.NoError(t, err)

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.POST("/login").
		SetJSON(gofight.D{
			"username": testAdmin,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			message := gjson.Get(r.Body.String(), "message")

			assert.Equal(t, ErrMissingLoginValues.Error(), message.String())
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			//nolint:staticcheck
			assert.Equal(t, "application/json; charset=utf-8", r.HeaderMap.Get("Content-Type"))
		})

	r.POST("/login").
		SetJSON(gofight.D{
			"username": testAdmin,
			"password": "test",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			message := gjson.Get(r.Body.String(), "message")
			assert.Equal(t, ErrFailedAuthentication.Error(), message.String())
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.POST("/login").
		SetJSON(gofight.D{
			"username": testAdmin,
			"password": testAdmin,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			message := gjson.Get(r.Body.String(), "message")
			assert.Equal(t, "login successfully", message.String())
			assert.Equal(t, http.StatusOK, r.Code)
			//nolint:staticcheck
			assert.True(t, strings.HasPrefix(r.HeaderMap.Get("Set-Cookie"), "jwt="))
			//nolint:staticcheck
			assert.True(
				t,
				strings.HasSuffix(
					r.HeaderMap.Get("Set-Cookie"),
					"; Path=/; Domain=example.com; Max-Age=3600",
				),
			)
		})
}

func TestParseToken(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Test 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS384", testAdmin),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", testAdmin),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestParseTokenRS256(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:            "test zone",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyFile:       "testdata/jwtRS256.key.pub",
		Authenticator:    defaultAuthenticator,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Test 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS384", testAdmin),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("RS256", testAdmin),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestParseTokenKeyFunc(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:         "test zone",
		KeyFunc:       keyFunc,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		// make sure it skips these settings
		Key:              []byte(""),
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "",
		PubKeyFile:       "",
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Test 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS384", testAdmin),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("RS256", testAdmin),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestRefreshHandlerRS256(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:            "test zone",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyFile:       "testdata/jwtRS256.key.pub",
		SendCookie:       true,
		CookieName:       testJWT,
		Authenticator:    defaultAuthenticator,
		RefreshResponse: func(c *gin.Context, token *core.Token) {
			cookie, err := c.Cookie(testJWT)
			if err != nil {
				log.Println(err)
			}

			expire := time.Unix(token.ExpiresAt, 0)
			c.JSON(http.StatusOK, gin.H{
				"code":    http.StatusOK,
				"token":   token.AccessToken,
				"expire":  expire.Format(time.RFC3339),
				"message": "refresh successfully",
				"cookie":  cookie,
			})
		},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	// Test missing refresh token
	r.POST("/auth/refresh_token").
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
		})

	// Test invalid refresh token
	r.POST("/auth/refresh_token").
		SetJSON(gofight.D{
			"refresh_token": "invalid_token",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	// Test valid refresh token
	refreshToken := getRefreshTokenFromLogin(handler)
	if refreshToken != "" {
		r.POST("/auth/refresh_token").
			SetJSON(gofight.D{
				"refresh_token": refreshToken,
			}).
			Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
				message := gjson.Get(r.Body.String(), "message")
				assert.Equal(t, "refresh successfully", message.String())
				assert.Equal(t, http.StatusOK, r.Code)
				// Verify we get new tokens
				accessToken := gjson.Get(r.Body.String(), "access_token")
				newRefreshToken := gjson.Get(r.Body.String(), "refresh_token")
				assert.NotEmpty(t, accessToken.String())
				assert.NotEmpty(t, newRefreshToken.String())
				assert.NotEqual(
					t,
					refreshToken,
					newRefreshToken.String(),
				) // New refresh token should be different
			})
	}
}

func TestRefreshHandler(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	// Test missing refresh token
	r.POST("/auth/refresh_token").
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
		})

	// Test invalid refresh token
	r.POST("/auth/refresh_token").
		SetJSON(gofight.D{
			"refresh_token": "invalid_token",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	// Test valid refresh token
	refreshToken := getRefreshTokenFromLogin(handler)
	if refreshToken != "" {
		r.POST("/auth/refresh_token").
			SetJSON(gofight.D{
				"refresh_token": refreshToken,
			}).
			Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
				assert.Equal(t, http.StatusOK, r.Code)
				// Verify we get new tokens
				accessToken := gjson.Get(r.Body.String(), "access_token")
				newRefreshToken := gjson.Get(r.Body.String(), "refresh_token")
				assert.NotEmpty(t, accessToken.String())
				assert.NotEmpty(t, newRefreshToken.String())
			})
	}
}

func TestValidRefreshToken(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:               "test zone",
		Key:                 key,
		Timeout:             time.Hour,
		MaxRefresh:          2 * time.Hour,
		RefreshTokenTimeout: 24 * time.Hour, // Long refresh token timeout
		Authenticator:       defaultAuthenticator,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	// Test that a valid refresh token still works
	refreshToken := getRefreshTokenFromLogin(handler)
	if refreshToken != "" {
		r.POST("/auth/refresh_token").
			SetJSON(gofight.D{
				"refresh_token": refreshToken,
			}).
			Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
				assert.Equal(t, http.StatusOK, r.Code)
			})
	}
}

func TestExpiredTokenOnRefreshHandler(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:               "test zone",
		Key:                 key,
		Timeout:             time.Hour,
		RefreshTokenTimeout: time.Millisecond, // Very short refresh token timeout
		Authenticator:       defaultAuthenticator,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	// Get a refresh token and wait for it to expire
	refreshToken := getRefreshTokenFromLogin(handler)
	if refreshToken != "" {
		// Wait for the refresh token to expire
		time.Sleep(2 * time.Millisecond)

		r.POST("/auth/refresh_token").
			SetJSON(gofight.D{
				"refresh_token": refreshToken,
			}).
			Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
				assert.Equal(t, http.StatusUnauthorized, r.Code)
			})
	}
}

func TestAuthorizer(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		Authorizer: func(c *gin.Context, data any) bool {
			return data.(string) == testAdmin
		},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "test"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusForbidden, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", testAdmin),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestParseTokenWithJsonNumber(t *testing.T) {
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
		ParseOptions: []jwt.ParserOption{jwt.WithJSONNumber()},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", testAdmin),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestClaimsDuringAuthorization(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		PayloadFunc: func(data any) jwt.MapClaims {
			if v, ok := data.(jwt.MapClaims); ok {
				return v
			}

			if reflect.TypeOf(data).String() != "string" {
				return jwt.MapClaims{}
			}

			var testkey string
			switch data.(string) {
			case testAdmin:
				testkey = "1234"
			case testUser:
				testkey = "5678"
			case "Guest":
				testkey = ""
			}
			// Set custom claim, to be checked in Authorizer method
			now := time.Now()
			return jwt.MapClaims{
				"identity": data.(string),
				"testkey":  testkey,
				"exp":      now.Add(time.Hour).Unix(),
				"iat":      now.Unix(),
				"nbf":      now.Unix(),
			}
		},
		Authenticator: func(c *gin.Context) (any, error) {
			var loginVals Login

			if err := c.BindJSON(&loginVals); err != nil {
				return "", ErrMissingLoginValues
			}

			userID := loginVals.Username
			password := loginVals.Password

			if userID == testAdmin && password == testPassword {
				return userID, nil
			}

			if userID == testUser && password == testUserPasswd {
				return userID, nil
			}

			return "Guest", ErrFailedAuthentication
		},
		Authorizer: func(c *gin.Context, user any) bool {
			jwtClaims := ExtractClaims(c)

			if jwtClaims["identity"] == "administrator" {
				return true
			}

			if jwtClaims["testkey"] == "1234" && jwtClaims["identity"] == testAdmin {
				return true
			}

			if jwtClaims["testkey"] == "5678" && jwtClaims["identity"] == testUser {
				return true
			}

			return false
		},
	})

	r := gofight.New()
	handler := ginHandler(authMiddleware)

	userToken, _, _ := authMiddleware.generateAccessToken(jwt.MapClaims{
		"identity": "administrator",
	})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})

	r.POST("/login").
		SetJSON(gofight.D{
			"username": testAdmin,
			"password": testAdmin,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			token := gjson.Get(r.Body.String(), "access_token")
			userToken = token.String()
			assert.Equal(t, http.StatusOK, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "test",
			"password": "test",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			token := gjson.Get(r.Body.String(), "access_token")
			userToken = token.String()
			assert.Equal(t, http.StatusOK, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func ConvertClaims(claims jwt.MapClaims) map[string]any {
	return map[string]any{}
}

func TestEmptyClaims(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(c *gin.Context) (any, error) {
			var loginVals Login
			userID := loginVals.Username
			password := loginVals.Password

			if userID == testAdmin && password == testPassword {
				return "", nil
			}

			if userID == testUser && password == testUserPasswd {
				return "Administrator", nil
			}

			return userID, ErrFailedAuthentication
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			assert.Empty(t, ExtractClaims(c))
			assert.Empty(t, ConvertClaims(ExtractClaims(c)))
			c.String(code, message)
		},
	})

	r := gofight.New()
	handler := ginHandler(authMiddleware)

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	assert.Empty(t, jwt.MapClaims{})
}

func TestUnauthorized(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})
}

func TestTokenExpire(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    -time.Second,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	// Test with missing refresh token (should return 400 bad request)
	r.POST("/auth/refresh_token").
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
		})
}

func TestTokenFromQueryString(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
		TokenLookup: "query:token",
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	userToken, _, _ := authMiddleware.generateAccessToken(jwt.MapClaims{
		"identity": testAdmin,
	})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello?token="+userToken).
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestTokenFromParamPath(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
		TokenLookup: "param:token",
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	userToken, _, _ := authMiddleware.generateAccessToken(jwt.MapClaims{
		"identity": testAdmin,
	})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/g/"+userToken+"/hello").
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestTokenFromCookieString(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
		TokenLookup: "cookie:token",
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	userToken, _, _ := authMiddleware.generateAccessToken(jwt.MapClaims{
		"identity": testAdmin,
	})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			token := gjson.Get(r.Body.String(), "token")
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Equal(t, "", token.String())
		})

	r.GET("/auth/hello").
		SetCookie(gofight.H{
			"token": userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})

	r.GET("/auth/hello").
		SetCookie(gofight.H{
			"token": userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			token := gjson.Get(r.Body.String(), "token")
			assert.Equal(t, http.StatusOK, r.Code)
			assert.Equal(t, userToken, token.String())
		})
}

func TestDefineTokenHeadName(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		TokenHeadName: "JWTTOKEN       ",
		Authenticator: defaultAuthenticator,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", testAdmin),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "JWTTOKEN " + makeTokenString("HS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestHTTPStatusMessageFunc(t *testing.T) {
	successError := errors.New("Successful test error")
	failedError := errors.New("Failed test error")
	successMessage := "Overwrite error message."

	authMiddleware, _ := New(&GinJWTMiddleware{
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,

		HTTPStatusMessageFunc: func(c *gin.Context, e error) string {
			if e == successError {
				return successMessage
			}

			return e.Error()
		},
	})

	successString := authMiddleware.HTTPStatusMessageFunc(nil, successError)
	failedString := authMiddleware.HTTPStatusMessageFunc(nil, failedError)

	assert.Equal(t, successMessage, successString)
	assert.NotEqual(t, successMessage, failedString)
}

func TestSendAuthorizationBool(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:             "test zone",
		Key:               key,
		Timeout:           time.Hour,
		MaxRefresh:        time.Hour * 24,
		Authenticator:     defaultAuthenticator,
		SendAuthorization: true,
		Authorizer: func(c *gin.Context, data any) bool {
			return data.(string) == testAdmin
		},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "test"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusForbidden, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", testAdmin),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			//nolint:staticcheck
			token := r.HeaderMap.Get("Authorization")
			assert.Equal(t, "Bearer "+makeTokenString("HS256", testAdmin), token)
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestExpiredTokenOnAuth(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:             "test zone",
		Key:               key,
		Timeout:           time.Hour,
		MaxRefresh:        time.Hour * 24,
		Authenticator:     defaultAuthenticator,
		SendAuthorization: true,
		Authorizer: func(c *gin.Context, data any) bool {
			return data.(string) == testAdmin
		},
		TimeFunc: func() time.Time {
			return time.Now().AddDate(0, 0, 1)
		},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", testAdmin),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})
}

func TestBadTokenOnRefreshHandler(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	// Test with bad refresh token
	r.POST("/auth/refresh_token").
		SetJSON(gofight.D{
			"refresh_token": "BadToken",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})
}

func TestExpiredField(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = testAdmin
	claims["orig_iat"] = 0
	tokenString, _ := token.SignedString(key)

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + tokenString,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			message := gjson.Get(r.Body.String(), "message")

			assert.Equal(t, ErrMissingExpField.Error(), message.String())
			assert.Equal(t, http.StatusBadRequest, r.Code)
		})

	// wrong format
	claims["exp"] = "wrongFormatForExpiry"
	tokenString, _ = token.SignedString(key)

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + tokenString,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			message := gjson.Get(r.Body.String(), "message")

			assert.Equal(t, ErrWrongFormatOfExp.Error(), strings.ToLower(message.String()))
			assert.Equal(t, http.StatusBadRequest, r.Code)
		})
}

func TestExpiredFieldRequiredParserOption(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		ParseOptions:  []jwt.ParserOption{jwt.WithExpirationRequired()},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = testAdmin
	claims["orig_iat"] = 0
	tokenString, _ := token.SignedString(key)

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + tokenString,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			message := gjson.Get(r.Body.String(), "message")

			assert.Equal(t, ErrMissingExpField.Error(), message.String())
			assert.Equal(t, http.StatusBadRequest, r.Code)
		})

	// wrong format
	claims["exp"] = "wrongFormatForExpiry"
	tokenString, _ = token.SignedString(key)

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + tokenString,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			message := gjson.Get(r.Body.String(), "message")

			assert.Equal(t, ErrWrongFormatOfExp.Error(), strings.ToLower(message.String()))
			assert.Equal(t, http.StatusBadRequest, r.Code)
		})
}

func TestCheckTokenString(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       1 * time.Second,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
		PayloadFunc: func(data any) jwt.MapClaims {
			if v, ok := data.(jwt.MapClaims); ok {
				return v
			}

			return nil
		},
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	userToken, _, _ := authMiddleware.generateAccessToken(jwt.MapClaims{
		"identity": testAdmin,
	})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})

	token, err := authMiddleware.ParseTokenString(userToken)
	assert.NoError(t, err)
	claims := ExtractClaimsFromToken(token)
	assert.Equal(t, testAdmin, claims["identity"])

	time.Sleep(2 * time.Second)

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	_, err = authMiddleware.ParseTokenString(userToken)
	assert.Error(t, err)
	assert.Equal(t, jwt.MapClaims{}, ExtractClaimsFromToken(nil))
}

func TestLogout(t *testing.T) {
	cookieName := testJWT
	cookieDomain := "example.com"
	// the middleware to test
	authMiddleware, _ := New(&GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		SendCookie:    true,
		CookieName:    cookieName,
		CookieDomain:  cookieDomain,
	})

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.POST("/logout").
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
			//nolint:staticcheck
			assert.Equal(
				t,
				fmt.Sprintf("%s=; Path=/; Domain=%s; Max-Age=0", cookieName, cookieDomain),
				r.HeaderMap.Get("Set-Cookie"),
			)
		})
}

func TestSetCookie(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	mw, _ := New(&GinJWTMiddleware{
		Realm:          "test zone",
		Key:            key,
		Timeout:        time.Hour,
		Authenticator:  defaultAuthenticator,
		SendCookie:     true,
		CookieName:     testJWT,
		CookieMaxAge:   time.Hour,
		CookieDomain:   "example.com",
		SecureCookie:   false,
		CookieHTTPOnly: true,
		TimeFunc:       time.Now,
	})

	token := makeTokenString("HS384", testAdmin)

	mw.SetCookie(c, token)

	cookies := w.Result().Cookies()

	assert.Len(t, cookies, 1)

	cookie := cookies[0]
	assert.Equal(t, testJWT, cookie.Name)
	assert.Equal(t, token, cookie.Value)
	assert.Equal(t, "/", cookie.Path)
	assert.Equal(t, "example.com", cookie.Domain)
	assert.Equal(t, true, cookie.HttpOnly)
}

func TestTokenGenerator(t *testing.T) {
	authMiddleware, err := New(&GinJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(c *gin.Context) (any, error) {
			return testAdmin, nil
		},
		PayloadFunc: func(data any) jwt.MapClaims {
			return jwt.MapClaims{
				"identity": data,
			}
		},
		Authorizer: func(c *gin.Context, data any) bool {
			return data == testAdmin
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		},
	})

	assert.NoError(t, err)

	userData := testAdmin
	ctx := context.Background()
	tokenPair, err := authMiddleware.TokenGenerator(ctx, userData)

	assert.NoError(t, err)
	assert.NotNil(t, tokenPair)
	assert.NotEmpty(t, tokenPair.AccessToken)
	assert.NotEmpty(t, tokenPair.RefreshToken)
	assert.Equal(t, "Bearer", tokenPair.TokenType)
	assert.True(t, tokenPair.ExpiresAt > time.Now().Unix())
	assert.True(t, tokenPair.CreatedAt <= time.Now().Unix())
	assert.True(t, tokenPair.ExpiresIn() > 0)

	// Validate that the access token is properly signed
	token, err := authMiddleware.ParseTokenString(tokenPair.AccessToken)
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, userData, claims["identity"])
}

func TestTokenGeneratorWithRevocation(t *testing.T) {
	authMiddleware, err := New(&GinJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(c *gin.Context) (any, error) {
			return testAdmin, nil
		},
		PayloadFunc: func(data any) jwt.MapClaims {
			return jwt.MapClaims{
				"identity": data,
			}
		},
	})

	assert.NoError(t, err)

	userData := testAdmin
	ctx := context.Background()

	// Generate first token pair
	oldTokenPair, err := authMiddleware.TokenGenerator(ctx, userData)
	assert.NoError(t, err)

	// Verify old refresh token exists in store
	storedData, err := authMiddleware.validateRefreshToken(ctx, oldTokenPair.RefreshToken)
	assert.NoError(t, err)
	assert.Equal(t, userData, storedData)

	// Generate new token pair with revocation
	newTokenPair, err := authMiddleware.TokenGeneratorWithRevocation(
		ctx,
		userData,
		oldTokenPair.RefreshToken,
	)
	assert.NoError(t, err)
	assert.NotNil(t, newTokenPair)

	// Verify refresh tokens are different (access tokens might be the same if generated in same second)
	assert.NotEqual(t, oldTokenPair.RefreshToken, newTokenPair.RefreshToken)

	// Verify old refresh token is revoked
	_, err = authMiddleware.validateRefreshToken(ctx, oldTokenPair.RefreshToken)
	assert.Error(t, err)

	// Verify new refresh token works
	storedData, err = authMiddleware.validateRefreshToken(ctx, newTokenPair.RefreshToken)
	assert.NoError(t, err)
	assert.Equal(t, userData, storedData)

	// Test revoking already revoked token (should not fail)
	anotherTokenPair, err := authMiddleware.TokenGeneratorWithRevocation(
		ctx,
		userData,
		oldTokenPair.RefreshToken,
	)
	assert.NoError(t, err)
	assert.NotNil(t, anotherTokenPair)

	// Test revoking non-existent token (should not fail)
	finalTokenPair, err := authMiddleware.TokenGeneratorWithRevocation(
		ctx,
		userData,
		"non_existent_token",
	)
	assert.NoError(t, err)
	assert.NotNil(t, finalTokenPair)
}

func TestTokenStruct(t *testing.T) {
	authMiddleware, err := New(&GinJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(c *gin.Context) (any, error) {
			return testAdmin, nil
		},
	})

	assert.NoError(t, err)

	userData := testAdmin
	ctx := context.Background()
	tokenPair, err := authMiddleware.TokenGenerator(ctx, userData)
	assert.NoError(t, err)

	// Test ExpiresIn method
	expiresIn := tokenPair.ExpiresIn()
	assert.True(t, expiresIn > 3500) // Should be close to 3600 (1 hour)
	assert.True(t, expiresIn <= 3600)

	// Test Token struct fields directly
	assert.NotEmpty(t, tokenPair.AccessToken)
	assert.Equal(t, "Bearer", tokenPair.TokenType)
	assert.NotEmpty(t, tokenPair.RefreshToken)
	assert.True(t, tokenPair.ExpiresAt > time.Now().Unix())
	assert.True(t, tokenPair.CreatedAt > 0)
	assert.True(t, tokenPair.CreatedAt <= time.Now().Unix())
}

func TestWWWAuthenticateHeader(t *testing.T) {
	testCases := []struct {
		name           string
		realm          string
		expectedHeader string
		authHeader     string
		tokenLookup    string
		setupRequest   func(r *gofight.RequestConfig)
		endpoint       string
	}{
		{
			name:           "default realm with invalid token",
			realm:          "test zone",
			expectedHeader: `JWT realm="test zone"`,
			authHeader:     "Bearer invalid_token",
			endpoint:       "/auth/hello",
			setupRequest: func(r *gofight.RequestConfig) {
				r.SetHeader(gofight.H{
					"Authorization": "Bearer invalid_token",
				})
			},
		},
		{
			name:           "custom realm with empty auth header",
			realm:          "my custom realm",
			expectedHeader: `JWT realm="my custom realm"`,
			authHeader:     "",
			endpoint:       "/auth/hello",
			setupRequest: func(r *gofight.RequestConfig) {
				// No Authorization header set
			},
		},
		{
			name:           "realm with special characters",
			realm:          `test-zone_123`,
			expectedHeader: `JWT realm="test-zone_123"`,
			authHeader:     "Bearer invalid",
			endpoint:       "/auth/hello",
			setupRequest: func(r *gofight.RequestConfig) {
				r.SetHeader(gofight.H{
					"Authorization": "Bearer invalid",
				})
			},
		},
		{
			name:           "expired token",
			realm:          "test zone",
			expectedHeader: `JWT realm="test zone"`,
			endpoint:       "/auth/hello",
			setupRequest: func(r *gofight.RequestConfig) {
				// Create an expired token
				token := jwt.New(jwt.GetSigningMethod("HS256"))
				claims := token.Claims.(jwt.MapClaims)
				claims["identity"] = testAdmin
				claims["exp"] = time.Now().Add(-time.Hour).Unix() // Expired 1 hour ago
				claims["orig_iat"] = time.Now().Add(-2 * time.Hour).Unix()
				tokenString, _ := token.SignedString(key)
				r.SetHeader(gofight.H{
					"Authorization": "Bearer " + tokenString,
				})
			},
		},
		{
			name:           "malformed token",
			realm:          "api realm",
			expectedHeader: `JWT realm="api realm"`,
			endpoint:       "/auth/hello",
			setupRequest: func(r *gofight.RequestConfig) {
				r.SetHeader(gofight.H{
					"Authorization": "Bearer not.a.valid.jwt.token",
				})
			},
		},
		{
			name:           "missing Bearer prefix",
			realm:          "test zone",
			expectedHeader: `JWT realm="test zone"`,
			endpoint:       "/auth/hello",
			setupRequest: func(r *gofight.RequestConfig) {
				r.SetHeader(gofight.H{
					"Authorization": "invalid_token_without_bearer",
				})
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authMiddleware, err := New(&GinJWTMiddleware{
				Realm:         tc.realm,
				Key:           key,
				Timeout:       time.Hour,
				MaxRefresh:    time.Hour * 24,
				Authenticator: defaultAuthenticator,
			})
			assert.NoError(t, err)

			handler := ginHandler(authMiddleware)
			r := gofight.New()

			request := r.GET(tc.endpoint)
			if tc.setupRequest != nil {
				tc.setupRequest(request)
			}

			request.Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
				assert.Equal(t, http.StatusUnauthorized, r.Code)
				assert.Equal(
					t,
					tc.expectedHeader,
					r.HeaderMap.Get("WWW-Authenticate"), //nolint:staticcheck
				)
			})
		})
	}
}

func TestWWWAuthenticateHeaderOnRefresh(t *testing.T) {
	authMiddleware, err := New(&GinJWTMiddleware{
		Realm:         "refresh realm",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})
	assert.NoError(t, err)

	handler := ginHandler(authMiddleware)
	r := gofight.New()

	// Test with invalid refresh token
	r.POST("/auth/refresh_token").
		SetJSON(gofight.D{
			"refresh_token": "invalid_refresh_token",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			//nolint:staticcheck
			assert.Equal(t, `JWT realm="refresh realm"`, r.HeaderMap.Get("WWW-Authenticate"))
		})
}

func TestWWWAuthenticateHeaderNotSetOnSuccess(t *testing.T) {
	authMiddleware, err := New(&GinJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(c *gin.Context) (any, error) {
			var loginVals Login
			if err := c.ShouldBind(&loginVals); err != nil {
				return "", ErrMissingLoginValues
			}

			if loginVals.Username == testAdmin && loginVals.Password == testPassword {
				return loginVals.Username, nil
			}

			return "", ErrFailedAuthentication
		},
	})
	assert.NoError(t, err)

	handler := ginHandler(authMiddleware)
	r := gofight.New()

	// Test successful login - WWW-Authenticate should not be set
	r.POST("/login").
		SetJSON(gofight.D{
			"username": testAdmin,
			"password": testAdmin,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
			assert.Empty(t, r.HeaderMap.Get("WWW-Authenticate")) //nolint:staticcheck
		})

	// Get a valid token for authenticated request
	token := makeTokenString("HS256", testAdmin)

	// Test successful authenticated request - WWW-Authenticate should not be set
	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + token,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
			assert.Empty(t, r.HeaderMap.Get("WWW-Authenticate")) //nolint:staticcheck
		})
}

func TestWWWAuthenticateHeaderWithDifferentRealms(t *testing.T) {
	realms := []string{
		"gin jwt",    // default
		"API Server", // with space
		"my-api",     // with dash
		"realm_test", // with underscore
		"MyApp v1.0", // with version
		"",           // empty (should use default)
	}

	for _, realm := range realms {
		t.Run(fmt.Sprintf("realm=%q", realm), func(t *testing.T) {
			authMiddleware, err := New(&GinJWTMiddleware{
				Realm:         realm,
				Key:           key,
				Timeout:       time.Hour,
				MaxRefresh:    time.Hour * 24,
				Authenticator: defaultAuthenticator,
			})
			assert.NoError(t, err)

			handler := ginHandler(authMiddleware)
			r := gofight.New()

			expectedRealm := realm
			if expectedRealm == "" {
				expectedRealm = "gin jwt" // default realm
			}

			r.GET("/auth/hello").
				SetHeader(gofight.H{
					"Authorization": "Bearer invalid",
				}).
				Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
					assert.Equal(t, http.StatusUnauthorized, r.Code)
					assert.Equal(
						t,
						fmt.Sprintf(`JWT realm="%s"`, expectedRealm),
						r.HeaderMap.Get("WWW-Authenticate"), //nolint:staticcheck
					)
				})
		})
	}
}
