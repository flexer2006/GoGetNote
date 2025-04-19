package jwt_service_test

import (
	jwtService "gogetnote/internal/auth/adapters/services"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	"gogetnote/internal/auth/domain/services"
)

const (
	msgUserIDMatches           = "user ID should match between domain and JWT claims"
	msgUsernameMatches         = "username should match between domain and JWT claims"
	msgSubjectMatches          = "subject should match user ID"
	msgExpiresAtMatches        = "expires at should match between domain and JWT claims"
	msgIssuedAtMatches         = "issued at should match between domain and JWT claims"
	msgZeroExpiresAtUnixEpoch  = "for zero expires at, should have Unix epoch value"
	msgZeroIssuedAtUnixEpoch   = "for zero issued at, should have Unix epoch value"
	msgPastTimeConverted       = "past time should be correctly converted"
	msgPastIssuedTimeConverted = "past issued time should be correctly converted"
	msgFarFutureTimeConverted  = "far future time should be correctly converted"
	msgSubjectMatchesComplexID = "subject should exactly match user ID even with special characters"
)

func TestDomainToJWTClaims(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	future := now.Add(15 * time.Minute).Truncate(time.Second)

	testCases := []struct {
		name              string
		domainClaims      services.JWTClaims
		expectedUserID    string
		expectedSubject   string
		expectedUsername  string
		expectedExpiresAt time.Time
		expectedIssuedAt  time.Time
	}{
		{
			name: "all fields filled",
			domainClaims: services.JWTClaims{
				UserID:    "user123",
				Username:  "testuser",
				IssuedAt:  now,
				ExpiresAt: future,
			},
			expectedUserID:    "user123",
			expectedSubject:   "user123",
			expectedUsername:  "testuser",
			expectedExpiresAt: future,
			expectedIssuedAt:  now,
		},
		{
			name: "empty username",
			domainClaims: services.JWTClaims{
				UserID:    "user456",
				Username:  "",
				IssuedAt:  now,
				ExpiresAt: future,
			},
			expectedUserID:    "user456",
			expectedSubject:   "user456",
			expectedUsername:  "",
			expectedExpiresAt: future,
			expectedIssuedAt:  now,
		},
		{
			name: "zero time values",
			domainClaims: services.JWTClaims{
				UserID:    "user789",
				Username:  "zerotimeuser",
				IssuedAt:  time.Time{},
				ExpiresAt: time.Time{},
			},
			expectedUserID:    "user789",
			expectedSubject:   "user789",
			expectedUsername:  "zerotimeuser",
			expectedExpiresAt: time.Time{},
			expectedIssuedAt:  time.Time{},
		},
	}

	for _, tcc := range testCases {
		t.Run(tcc.name, func(t *testing.T) {
			jwtClaims := jwtService.GetDomainToJWTClaimsForTest(tcc.domainClaims)

			assert.Equal(t, tcc.expectedUserID, jwtClaims.UserID, msgUserIDMatches)

			assert.Equal(t, tcc.expectedUsername, jwtClaims.Username, msgUsernameMatches)

			assert.Equal(t, tcc.expectedSubject, jwtClaims.Subject, msgSubjectMatches)

			if !tcc.expectedExpiresAt.IsZero() {
				expectedNumericDate := jwt.NewNumericDate(tcc.expectedExpiresAt)
				assert.Equal(t, expectedNumericDate.Unix(), jwtClaims.ExpiresAt.Unix(), msgExpiresAtMatches)
			} else {
				assert.Equal(t, time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC), jwtClaims.ExpiresAt.Time,
					msgZeroExpiresAtUnixEpoch)
			}

			if !tcc.expectedIssuedAt.IsZero() {
				expectedNumericDate := jwt.NewNumericDate(tcc.expectedIssuedAt)
				assert.Equal(t, expectedNumericDate.Unix(), jwtClaims.IssuedAt.Unix(), msgIssuedAtMatches)
			} else {
				assert.Equal(t, time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC), jwtClaims.IssuedAt.Time,
					msgZeroIssuedAtUnixEpoch)
			}
		})
	}
}

func TestDomainToJWTClaimsEdgeCases(t *testing.T) {
	t.Run("past time", func(t *testing.T) {
		past := time.Now().Add(-24 * time.Hour).Truncate(time.Second)

		domainClaims := services.JWTClaims{
			UserID:    "expired-user",
			Username:  "expireduser",
			IssuedAt:  past,
			ExpiresAt: past,
		}

		jwtClaims := jwtService.GetDomainToJWTClaimsForTest(domainClaims)

		expectedExpiresAt := jwt.NewNumericDate(past)
		expectedIssuedAt := jwt.NewNumericDate(past)

		assert.Equal(t, expectedExpiresAt.Unix(), jwtClaims.ExpiresAt.Unix(), msgPastTimeConverted)
		assert.Equal(t, expectedIssuedAt.Unix(), jwtClaims.IssuedAt.Unix(), msgPastIssuedTimeConverted)
	})

	t.Run("far future", func(t *testing.T) {
		farFuture := time.Now().Add(10 * 365 * 24 * time.Hour).Truncate(time.Second)

		domainClaims := services.JWTClaims{
			UserID:    "future-user",
			Username:  "futureuser",
			IssuedAt:  time.Now().Truncate(time.Second),
			ExpiresAt: farFuture,
		}

		jwtClaims := jwtService.GetDomainToJWTClaimsForTest(domainClaims)

		expectedExpiresAt := jwt.NewNumericDate(farFuture)

		assert.Equal(t, expectedExpiresAt.Unix(), jwtClaims.ExpiresAt.Unix(), msgFarFutureTimeConverted)
	})

	t.Run("subject matches user id", func(t *testing.T) {
		complexUserID := "user-with-special_chars.123@domain"

		domainClaims := services.JWTClaims{
			UserID:    complexUserID,
			Username:  "complexuser",
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}

		jwtClaims := jwtService.GetDomainToJWTClaimsForTest(domainClaims)

		assert.Equal(t, complexUserID, jwtClaims.Subject, msgSubjectMatchesComplexID)
	})
}
