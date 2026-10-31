// Example demonstrating the TokenGenerator functionality
package main

import (
	"context"
	"log"
	"time"

	jwt "github.com/appleboy/gin-jwt/v3"

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

	// Create context for token operations
	ctx := context.Background()

	// Generate a complete token pair (access + refresh tokens)
	log.Println("=== Generating Token Pair ===")
	tokenPair, err := authMiddleware.TokenGenerator(ctx, userData)
	if err != nil {
		log.Fatal("Failed to generate token pair:", err)
	}

	log.Printf("Access Token: %s\n", tokenPair.AccessToken[:50]+"...")
	log.Printf("Token Type: %s\n", tokenPair.TokenType)
	log.Printf("Refresh Token: %s\n", tokenPair.RefreshToken)
	log.Printf("Expires At: %d (%s)\n", tokenPair.ExpiresAt, time.Unix(tokenPair.ExpiresAt, 0))
	log.Printf("Created At: %d (%s)\n", tokenPair.CreatedAt, time.Unix(tokenPair.CreatedAt, 0))
	log.Printf("Expires In: %d seconds\n", tokenPair.ExpiresIn())

	// Simulate refresh token usage
	log.Println("\n=== Refreshing Token Pair ===")
	newTokenPair, err := authMiddleware.TokenGeneratorWithRevocation(
		ctx,
		userData,
		tokenPair.RefreshToken,
	)
	if err != nil {
		log.Fatal("Failed to refresh token pair:", err)
	}

	log.Printf("New Access Token: %s\n", newTokenPair.AccessToken[:50]+"...")
	log.Printf("New Refresh Token: %s\n", newTokenPair.RefreshToken)
	log.Printf(
		"Old refresh token revoked: %t\n",
		tokenPair.RefreshToken != newTokenPair.RefreshToken,
	)

	// Verify old refresh token is invalid
	log.Println("\n=== Verifying Old Token Revocation ===")
	_, err = authMiddleware.TokenGeneratorWithRevocation(ctx, userData, tokenPair.RefreshToken)
	if err != nil {
		log.Printf("Old refresh token correctly rejected: %s\n", err)
	}

	log.Println("\n=== Token Generation Complete! ===")
	log.Println("You can now use these tokens without needing middleware handlers!")
}
