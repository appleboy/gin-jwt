// Example demonstrating the TokenGenerator functionality
package main

import (
	"fmt"
	"log"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	gojwt "github.com/golang-jwt/jwt/v5"
)

func main() {
	// Initialize the middleware
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:      "example zone",
		Key:        []byte("secret key"),
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		PayloadFunc: func(data any) gojwt.MapClaims {
			return gojwt.MapClaims{
				"user_id": data,
			}
		},
	})
	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	// Example user data
	userData := "user123"

	// Generate a complete token pair (access + refresh tokens)
	fmt.Println("=== Generating Token Pair ===")
	tokenPair, err := authMiddleware.TokenGenerator(userData)
	if err != nil {
		log.Fatal("Failed to generate token pair:", err)
	}

	fmt.Printf("Access Token: %s\n", tokenPair.AccessToken[:50]+"...")
	fmt.Printf("Token Type: %s\n", tokenPair.TokenType)
	fmt.Printf("Refresh Token: %s\n", tokenPair.RefreshToken)
	fmt.Printf("Expires At: %d (%s)\n", tokenPair.ExpiresAt, time.Unix(tokenPair.ExpiresAt, 0))
	fmt.Printf("Created At: %d (%s)\n", tokenPair.CreatedAt, time.Unix(tokenPair.CreatedAt, 0))
	fmt.Printf("Expires In: %d seconds\n", tokenPair.ExpiresIn())

	// Simulate refresh token usage
	fmt.Println("\n=== Refreshing Token Pair ===")
	newTokenPair, err := authMiddleware.TokenGeneratorWithRevocation(userData, tokenPair.RefreshToken)
	if err != nil {
		log.Fatal("Failed to refresh token pair:", err)
	}

	fmt.Printf("New Access Token: %s\n", newTokenPair.AccessToken[:50]+"...")
	fmt.Printf("New Refresh Token: %s\n", newTokenPair.RefreshToken)
	fmt.Printf("Old refresh token revoked: %t\n", tokenPair.RefreshToken != newTokenPair.RefreshToken)

	// Verify old refresh token is invalid
	fmt.Println("\n=== Verifying Old Token Revocation ===")
	_, err = authMiddleware.TokenGeneratorWithRevocation(userData, tokenPair.RefreshToken)
	if err != nil {
		fmt.Printf("Old refresh token correctly rejected: %s\n", err)
	}

	fmt.Println("\n=== Token Generation Complete! ===")
	fmt.Println("You can now use these tokens without needing middleware handlers!")
}
