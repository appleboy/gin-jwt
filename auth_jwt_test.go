package jwt

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/buger/jsonparser"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gopkg.in/appleboy/gofight.v2"
	"gopkg.in/dgrijalva/jwt-go.v3"
)

var (
	key = []byte("secret key")

	rsaPrivateKeyString = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDm5P69FhprYEz6BI6Dt0KaXheNG5LMiahMGsmW2/4ydwWQnB1t
Lf5OhRxJV8NV+k+e1HiP+ovzNWJ610hjDMhTtRahmgs0HAJ8kpQe4QCZAtHgbc6q
OIKK0c8+v0UGYqVrxJA0bASIhjTXOjPLvZqEU2p2IMacrjLecXKTW0/YEwIDAQAB
AoGBAKFI5pSIow3MaBjhI/foBHM2NLdRwnpz0gbPU2+43li8ATwhgQCp9xE8NCUb
VAxz3DgzbMAOIMJT0SXDygG+hRN4GCRX7xqtLt67t38Nr25Qgf8V+NPbLp4sHPFo
Fk2ODt5XxfE1Ca4tNYBSNPg8ozz+xjRPhuqT5lskXPVNrZ2xAkEA+Fmp0bDa1SSo
LAGg0YUee6NmMh+VoyuhSKNfkKGNSzPYz0PBFljtkYP0C16RHXBs/BdIc7tqSiIN
gFFer9IsmwJBAO4Br8MCjiGv8nXe8tx/IViJR0XM67SGHl8P9XSNa3p6Ih+F2nbG
rlPR2B4quVEFyKkRohUPkbs5ahrle/FqLekCQDHMIM4IDUkRyZrRVMLOU3dtIy/H
v4RxWiyrfZ0Nl7xNkBq3Nj9Z44D7GXMyKhziDyhZLtDt8nkc7OIe7sKIfSMCQQDF
pBTmZXrNsqQvCYK3Y8K3GNhcuDyLXkxeOIxlywITZNRtROQTeg1NgZZsBqJ5C8qD
yybDQniL9rOLvkFcSgXxAkA5GW4lJpmo2ZxDynVjfKkOlmwpAGXHWk4ta8vVzhEQ
blwQMKuzuVTPek5c2R3RXbSxxdivaFoIdbcYzWEPtqu4
-----END RSA PRIVATE KEY-----`

	rsaPublicKeyString = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDm5P69FhprYEz6BI6Dt0KaXheN
G5LMiahMGsmW2/4ydwWQnB1tLf5OhRxJV8NV+k+e1HiP+ovzNWJ610hjDMhTtRah
mgs0HAJ8kpQe4QCZAtHgbc6qOIKK0c8+v0UGYqVrxJA0bASIhjTXOjPLvZqEU2p2
IMacrjLecXKTW0/YEwIDAQAB
-----END PUBLIC KEY-----`

	rsaPrivateKey, _ = jwt.ParseRSAPrivateKeyFromPEM([]byte(rsaPrivateKeyString))
	rsaPublicKey, _  = jwt.ParseRSAPublicKeyFromPEM([]byte(rsaPublicKeyString))
)

func makeTokenString(SigningAlgorithm string, username string) string {

	if SigningAlgorithm == "" {
		SigningAlgorithm = "HS256"
	}

	token := jwt.New(jwt.GetSigningMethod(SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = username
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["orig_iat"] = time.Now().Unix()
	tokenString, _ := token.SignedString(key)

	return tokenString
}

func makeAsymmetricTokenString(SigningAlgorithm string, username string) string {

	token := jwt.New(jwt.GetSigningMethod(SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = username
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["orig_iat"] = time.Now().Unix()
	tokenString, _ := token.SignedString(rsaPrivateKey)

	return tokenString
}

func TestMissingRealm(t *testing.T) {

	authMiddleware := &GinJWTMiddleware{
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "", true
			}

			return "", false
		},
	}

	err := authMiddleware.MiddlewareInit()

	assert.Error(t, err)
	assert.Equal(t, "realm is required", err.Error())
}

func TestMissingKey(t *testing.T) {

	authMiddleware := &GinJWTMiddleware{
		Realm:      "test zone",
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "", true
			}

			return "", false
		},
	}

	err := authMiddleware.MiddlewareInit()

	assert.Error(t, err)
	assert.Equal(t, "secret key is required", err.Error())
}

func TestMissingPrivateKey(t *testing.T) {

	authMiddleware := &GinJWTMiddleware{
		Realm:            "test zone",
		SigningAlgorithm: "RS256",
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "", true
			}

			return "", false
		},
	}

	err := authMiddleware.MiddlewareInit()

	assert.Error(t, err)
	assert.Equal(t, "private key is required", err.Error())
}

func TestMissingPublicKey(t *testing.T) {

	authMiddleware := &GinJWTMiddleware{
		Realm:            "test zone",
		SigningAlgorithm: "RS256",
		SignKey:          rsaPrivateKey,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "", true
			}

			return "", false
		},
	}

	err := authMiddleware.MiddlewareInit()

	assert.Error(t, err)
	assert.Equal(t, "public key is required", err.Error())
}

func TestMissingTimeOut(t *testing.T) {

	authMiddleware := &GinJWTMiddleware{
		Realm: "test zone",
		Key:   key,
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "", true
			}

			return "", false
		},
	}

	authMiddleware.MiddlewareInit()

	assert.Equal(t, time.Hour, authMiddleware.Timeout)
}

func TestMissingTokenLookup(t *testing.T) {

	authMiddleware := &GinJWTMiddleware{
		Realm: "test zone",
		Key:   key,
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "", true
			}

			return "", false
		},
	}

	authMiddleware.MiddlewareInit()

	assert.Equal(t, "header:Authorization", authMiddleware.TokenLookup)
}

func helloHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"text": "Hello World.",
	})
}

func ginHandler(auth *GinJWTMiddleware) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	r.POST("/login", auth.LoginHandler)

	group := r.Group("/auth")
	group.Use(auth.MiddlewareFunc())
	{
		group.GET("/hello", helloHandler)
		group.GET("/refresh_token", auth.RefreshHandler)
	}

	return r
}

func TestInternalServerError(t *testing.T) {
	// the middleware to test
	authMiddleware := &GinJWTMiddleware{}

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			data := []byte(r.Body.String())

			message, _ := jsonparser.GetString(data, "message")

			assert.Equal(t, "realm is required", message)
			assert.Equal(t, http.StatusInternalServerError, r.Code)
		})
}

func TestMissingAuthenticatorForLoginHandler(t *testing.T) {

	authMiddleware := &GinJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
	}

	handler := ginHandler(authMiddleware)
	r := gofight.New()

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "admin",
			"password": "admin",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			data := []byte(r.Body.String())
			message, _ := jsonparser.GetString(data, "message")

			assert.Equal(t, "Missing define authenticator func", message)
			assert.Equal(t, http.StatusInternalServerError, r.Code)
		})
}

func TestLoginHandler(t *testing.T) {

	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm: "test zone",
		Key:   key,
		PayloadFunc: func(userId string) map[string]interface{} {
			// Set custom claim, to be checked in Authorizator method
			return map[string]interface{}{"testkey": "testval", "exp": 0}
		},
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "", true
			}

			return "", false
		},
		Authorizator: func(userId string, c *gin.Context) bool {
			return true
		},
	}

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "admin",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			data := []byte(r.Body.String())

			message, _ := jsonparser.GetString(data, "message")

			assert.Equal(t, "Missing Username or Password", message)
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "application/json; charset=utf-8", r.HeaderMap.Get("Content-Type"))
		})

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "admin",
			"password": "test",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			data := []byte(r.Body.String())

			message, _ := jsonparser.GetString(data, "message")

			assert.Equal(t, "Incorrect Username / Password", message)
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "admin",
			"password": "admin",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func performRequest(r http.Handler, method, path string, token string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, nil)

	if token != "" {
		req.Header.Set("Authorization", token)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

func TestParseToken(t *testing.T) {
	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return userId, true
			}

			return userId, false
		},
	}

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
			"Authorization": "Bearer " + makeTokenString("HS384", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestRefreshHandler(t *testing.T) {
	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return userId, true
			}

			return userId, false
		},
	}

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Test 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestExpriedTokenOnRefreshHandler(t *testing.T) {
	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm:   "test zone",
		Key:     key,
		Timeout: time.Hour,
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return userId, true
			}

			return userId, false
		},
	}

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = "admin"
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["orig_iat"] = 0
	tokenString, _ := token.SignedString(key)

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + tokenString,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})
}

func TestAuthorizator(t *testing.T) {
	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return userId, true
			}
			return userId, false
		},
		Authorizator: func(userId string, c *gin.Context) bool {
			if userId != "admin" {
				return false
			}

			return true
		},
	}

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
			"Authorization": "Bearer " + makeTokenString("HS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestAuthorizatorRS256(t *testing.T) {
	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm:            "test zone",
		SigningAlgorithm: "RS256",
		SignKey:          rsaPrivateKey,
		VerifyKey:        rsaPublicKey,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return userId, true
			}
			return userId, false
		},
		Authorizator: func(userId string, c *gin.Context) bool {
			if userId != "admin" {
				return false
			}

			return true
		},
	}

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeAsymmetricTokenString("RS256", "test"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusForbidden, r.Code)
		})

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeAsymmetricTokenString("RS256", "admin"),
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestClaimsDuringAuthorization(t *testing.T) {
	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		PayloadFunc: func(userId string) map[string]interface{} {
			var testkey string
			switch userId {
			case "admin":
				testkey = "1234"
			case "test":
				testkey = "5678"
			}
			// Set custom claim, to be checked in Authorizator method
			return map[string]interface{}{"testkey": testkey, "exp": 0}
		},
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "", true
			}

			if userId == "test" && password == "test" {
				return "Administrator", true
			}

			return userId, false
		},
		Authorizator: func(userId string, c *gin.Context) bool {
			jwtClaims := ExtractClaims(c)

			if jwtClaims["testkey"] == "1234" && jwtClaims["id"] == "admin" {
				return true
			}

			if jwtClaims["testkey"] == "5678" && jwtClaims["id"] == "Administrator" {
				return true
			}

			return false
		},
	}

	r := gofight.New()
	handler := ginHandler(authMiddleware)

	userToken := authMiddleware.TokenGenerator("admin")

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "admin",
			"password": "admin",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			data := []byte(r.Body.String())

			token, _ := jsonparser.GetString(data, "token")
			userToken = token
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
			data := []byte(r.Body.String())

			token, _ := jsonparser.GetString(data, "token")
			userToken = token
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

func TestEmptyClaims(t *testing.T) {

	var jwtClaims map[string]interface{}

	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "", true
			}

			if userId == "test" && password == "test" {
				return "Administrator", true
			}

			return userId, false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			jwtClaims = ExtractClaims(c)
			c.String(code, message)
		},
	}

	r := gofight.New()
	handler := ginHandler(authMiddleware)

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer 1234",
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	assert.Empty(t, jwtClaims)
}

func TestUnauthorized(t *testing.T) {
	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return userId, true
			}
			return userId, false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
	}

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
	authMiddleware := &GinJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: -time.Second,
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return userId, true
			}
			return userId, false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
	}

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	userToken := authMiddleware.TokenGenerator("admin")

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})
}

func TestTokenFromQueryString(t *testing.T) {
	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm:   "test zone",
		Key:     key,
		Timeout: time.Hour,
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return userId, true
			}
			return userId, false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
		TokenLookup: "query:token",
	}

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	userToken := authMiddleware.TokenGenerator("admin")

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/refresh_token?token="+userToken).
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestTokenFromCookieString(t *testing.T) {
	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm:   "test zone",
		Key:     key,
		Timeout: time.Hour,
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return userId, true
			}
			return userId, false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.String(code, message)
		},
		TokenLookup: "cookie:token",
	}

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	userToken := authMiddleware.TokenGenerator("admin")

	r.GET("/auth/refresh_token").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})

	r.GET("/auth/refresh_token").
		SetCookie(gofight.H{
			"token": userToken,
		}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestDefineTokenHeadName(t *testing.T) {
	// the middleware to test
	authMiddleware := &GinJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		TokenHeadName: "JWTTOKEN       ",
		Authenticator: func(userId string, password string, c *gin.Context) (string, bool) {
			if userId == "admin" && password == "admin" {
				return userId, true
			}
			return userId, false
		},
	}

	handler := ginHandler(authMiddleware)

	r := gofight.New()

	r.GET("/auth/hello").
		SetHeader(gofight.H{
			"Authorization": "Bearer " + makeTokenString("HS256", "admin"),
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
