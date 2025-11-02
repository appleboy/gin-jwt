package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestToken(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(time.Hour).Unix()
	createdAt := now.Unix()

	token := &Token{
		AccessToken:  "test.access.token",
		TokenType:    "Bearer",
		RefreshToken: "test-refresh-token",
		ExpiresAt:    expiresAt,
		CreatedAt:    createdAt,
	}

	// Test basic fields
	assert.Equal(t, "test.access.token", token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Equal(t, "test-refresh-token", token.RefreshToken)
	assert.Equal(t, expiresAt, token.ExpiresAt)
	assert.Equal(t, createdAt, token.CreatedAt)

	// Test ExpiresIn method
	expiresIn := token.ExpiresIn()
	assert.True(t, expiresIn > 3500) // Should be close to 3600 (1 hour)
	assert.True(t, expiresIn <= 3600)
}

func TestTokenExpiresIn(t *testing.T) {
	testCases := []struct {
		name      string
		expiresAt int64
		expected  int64
	}{
		{
			name:      "Future expiry",
			expiresAt: time.Now().Add(30 * time.Minute).Unix(),
			expected:  30 * 60, // approximately 30 minutes
		},
		{
			name:      "Past expiry",
			expiresAt: time.Now().Add(-30 * time.Minute).Unix(),
			expected:  -30 * 60, // approximately -30 minutes
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := &Token{ExpiresAt: tc.expiresAt}
			expiresIn := token.ExpiresIn()

			// Allow for some time difference due to test execution
			diff := expiresIn - tc.expected
			assert.True(
				t,
				diff >= -5 && diff <= 5,
				"ExpiresIn should be within 5 seconds of expected",
			)
		})
	}
}
