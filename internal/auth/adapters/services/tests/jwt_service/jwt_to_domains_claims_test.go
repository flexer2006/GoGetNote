package jwt_service_test

import (
	jwtService "gogetnote/internal/auth/adapters/services"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

const (
	msgExpiresAtTimeMatches         = "expires at should be correctly converted from JWT to domain format"
	msgIssuedAtTimeMatches          = "issued at should be correctly converted from JWT to domain format"
	msgNilExpiresAtHandling         = "nil expires at should be handled correctly"
	msgNilIssuedAtHandling          = "nil issued at should be handled correctly"
	msgPastExpiresAtConverted       = "past expiration time should be correctly converted"
	msgPastIssuedAtConverted        = "past issued time should be correctly converted"
	msgCurrentTimeConverted         = "current time should be correctly converted"
	msgZeroTimeNumericDateConverted = "numeric date with zero time should be correctly converted"
)

func TestJWTToDomainClaims(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	future := now.Add(15 * time.Minute).Truncate(time.Second)

	testCases := []struct {
		name              string
		jwtClaims         jwtService.ClaimsJwt
		expectedUserID    string
		expectedUsername  string
		expectedExpiresAt time.Time
		expectedIssuedAt  time.Time
	}{
		{
			name: "all fields filled",
			jwtClaims: jwtService.ClaimsJwt{
				UserID:   "user123",
				Username: "testuser",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(future),
					IssuedAt:  jwt.NewNumericDate(now),
					Subject:   "user123",
				},
			},
			expectedUserID:    "user123",
			expectedUsername:  "testuser",
			expectedExpiresAt: future,
			expectedIssuedAt:  now,
		},
		{
			name: "empty username",
			jwtClaims: jwtService.ClaimsJwt{
				UserID:   "user456",
				Username: "",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(future),
					IssuedAt:  jwt.NewNumericDate(now),
					Subject:   "user456",
				},
			},
			expectedUserID:    "user456",
			expectedUsername:  "",
			expectedExpiresAt: future,
			expectedIssuedAt:  now,
		},
		{
			name: "nil time fields",
			jwtClaims: jwtService.ClaimsJwt{
				UserID:   "user789",
				Username: "zerotimeuser",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: nil,
					IssuedAt:  nil,
					Subject:   "user789",
				},
			},
			expectedUserID:    "user789",
			expectedUsername:  "zerotimeuser",
			expectedExpiresAt: time.Time{},
			expectedIssuedAt:  time.Time{},
		},
	}

	for _, tcc := range testCases {
		t.Run(tcc.name, func(t *testing.T) {
			domainClaims := jwtService.GetJWTToDomainClaimsForTest(tcc.jwtClaims)

			assert.Equal(t, tcc.expectedUserID, domainClaims.UserID, msgUserIDMatches)

			assert.Equal(t, tcc.expectedUsername, domainClaims.Username, msgUsernameMatches)

			if tcc.jwtClaims.ExpiresAt != nil {
				assert.Equal(t, tcc.expectedExpiresAt, domainClaims.ExpiresAt, msgExpiresAtTimeMatches)
			} else {
				assert.True(t, domainClaims.ExpiresAt.IsZero(), msgNilExpiresAtHandling)
			}

			if tcc.jwtClaims.IssuedAt != nil {
				assert.Equal(t, tcc.expectedIssuedAt, domainClaims.IssuedAt, msgIssuedAtTimeMatches)
			} else {
				assert.True(t, domainClaims.IssuedAt.IsZero(), msgNilIssuedAtHandling)
			}
		})
	}
}

func TestJWTToDomainClaimsEdgeCases(t *testing.T) {
	t.Run("past time", func(t *testing.T) {
		past := time.Now().Add(-24 * time.Hour).Truncate(time.Second)

		jwtClaims := jwtService.ClaimsJwt{
			UserID:   "expired-user",
			Username: "expireduser",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(past),
				IssuedAt:  jwt.NewNumericDate(past),
				Subject:   "expired-user",
			},
		}

		domainClaims := jwtService.GetJWTToDomainClaimsForTest(jwtClaims)

		assert.Equal(t, past, domainClaims.ExpiresAt, msgPastExpiresAtConverted)
		assert.Equal(t, past, domainClaims.IssuedAt, msgPastIssuedAtConverted)
	})

	t.Run("far future", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		farFuture := now.Add(10 * 365 * 24 * time.Hour).Truncate(time.Second) // roughly 10 years

		jwtClaims := jwtService.ClaimsJwt{
			UserID:   "future-user",
			Username: "futureuser",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(farFuture),
				IssuedAt:  jwt.NewNumericDate(now),
				Subject:   "future-user",
			},
		}

		domainClaims := jwtService.GetJWTToDomainClaimsForTest(jwtClaims)

		assert.Equal(t, farFuture, domainClaims.ExpiresAt, msgFarFutureTimeConverted)
		assert.Equal(t, now, domainClaims.IssuedAt, msgCurrentTimeConverted)
	})

	t.Run("numeric date with zero time", func(t *testing.T) {
		zeroTime := time.Time{}

		jwtClaims := jwtService.ClaimsJwt{
			UserID:   "zero-time-user",
			Username: "zerotimeuser",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(zeroTime),
				IssuedAt:  jwt.NewNumericDate(zeroTime),
				Subject:   "zero-time-user",
			},
		}

		domainClaims := jwtService.GetJWTToDomainClaimsForTest(jwtClaims)

		expectedTime := jwt.NewNumericDate(zeroTime).Time

		assert.Equal(t, expectedTime, domainClaims.ExpiresAt, msgZeroTimeNumericDateConverted)
		assert.Equal(t, expectedTime, domainClaims.IssuedAt, msgZeroTimeNumericDateConverted)
	})
}
