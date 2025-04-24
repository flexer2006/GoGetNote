package services_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	cryptobcrypt "golang.org/x/crypto/bcrypt"

	"gogetnote/internal/auth/adapters/services"
	domainservices "gogetnote/internal/auth/domain/services"
	svc "gogetnote/internal/auth/ports/services"
	"gogetnote/pkg/logger"

	bcryptService "gogetnote/internal/auth/adapters/services"
	jwtService "gogetnote/internal/auth/adapters/services"
	ports "gogetnote/internal/auth/ports/services"
)

//nolint:gosec
const (
	msgEmptyPasswordError                = "should return error for empty password"
	msgShortPasswordError                = "should return error for short password"
	msgNoErrorValidPassword              = "should not return error for valid password"
	msgHashNotEmpty                      = "hash should not be empty"
	msgErrorInvalidPassword              = "error should be err invalid password"
	msgHashVerifiable                    = "created hash should be verifiable"
	msgHashEmptyInvalidPassword          = "hash should be empty for invalid password"
	msgHashEmptyShortPassword            = "hash should be empty for short password"
	msgNoErrorFirstPassword              = "should not return error for first password"
	msgNoErrorSecondPassword             = "should not return error for second password"
	msgDifferentHashesDifferentPasswords = "hashes of different passwords should differ"
	msgNoErrorFirstHash                  = "should not return error for first hash"
	msgNoErrorSecondHash                 = "should not return error for second hash"
	msgDifferentHashesSamePassword       = "hashes of same password should differ due to salt"
	msgNoErrorNilContext                 = "should not return error with nil context"
	msgNoErrorBackgroundContext          = "should not return error with background context"
	msgHashNotEmptyNilContext            = "hash should not be empty with nil context"
	msgHashNotEmptyBackgroundContext     = "hash should not be empty with background context"
	msgNoErrorExtractingCost             = "should not return error when extracting cost"
)

func TestHashSuccess(t *testing.T) {
	service := bcryptService.NewBcrypt(10)
	validPassword := "validPassword123"
	ctx := context.Background()

	hash, err := service.Hash(ctx, validPassword)

	require.NoError(t, err, msgNoErrorValidPassword)
	assert.NotEmpty(t, hash, msgHashNotEmpty)

	err = cryptobcrypt.CompareHashAndPassword([]byte(hash), []byte(validPassword))
	assert.NoError(t, err, msgHashVerifiable)
}

func TestHashEmptyPassword(t *testing.T) {
	service := bcryptService.NewBcrypt(10)
	emptyPassword := ""
	ctx := context.Background()

	hash, err := service.Hash(ctx, emptyPassword)

	require.Error(t, err, msgEmptyPasswordError)
	assert.Empty(t, hash, msgHashEmptyInvalidPassword)
	assert.ErrorIs(t, err, domainservices.ErrInvalidPassword, msgErrorInvalidPassword)
}

func TestHashShortPassword(t *testing.T) {
	service := bcryptService.NewBcrypt(10)
	shortPassword := "short"
	ctx := context.Background()

	hash, err := service.Hash(ctx, shortPassword)

	require.Error(t, err, msgShortPasswordError)
	assert.Empty(t, hash, msgHashEmptyShortPassword)
	require.ErrorIs(t, err, domainservices.ErrInvalidPassword, msgErrorInvalidPassword)
}

func TestHashDifferentPasswordsDifferentHashes(t *testing.T) {
	service := bcryptService.NewBcrypt(10)
	password1 := "password123"
	password2 := "password456"
	ctx := context.Background()

	hash1, err1 := service.Hash(ctx, password1)
	hash2, err2 := service.Hash(ctx, password2)

	assert.NoError(t, err1, msgNoErrorFirstPassword)
	assert.NoError(t, err2, msgNoErrorSecondPassword)
	assert.NotEqual(t, hash1, hash2, msgDifferentHashesDifferentPasswords)
}

func TestHashSamePasswordsDifferentHashes(t *testing.T) {
	service := bcryptService.NewBcrypt(10)
	password := "samePassword123"
	ctx := context.Background()

	hash1, err1 := service.Hash(ctx, password)
	hash2, err2 := service.Hash(ctx, password)

	assert.NoError(t, err1, msgNoErrorFirstHash)
	assert.NoError(t, err2, msgNoErrorSecondHash)
	assert.NotEqual(t, hash1, hash2, msgDifferentHashesSamePassword)
}

func TestHashContextIgnored(t *testing.T) {
	service := bcryptService.NewBcrypt(10)
	password := "testPassword123"

	nilCtx := context.Context(nil)
	bgCtx := context.Background()

	hash1, err1 := service.Hash(nilCtx, password)
	hash2, err2 := service.Hash(bgCtx, password)

	assert.NoError(t, err1, msgNoErrorNilContext)
	assert.NoError(t, err2, msgNoErrorBackgroundContext)
	assert.NotEmpty(t, hash1, msgHashNotEmptyNilContext)
	assert.NotEmpty(t, hash2, msgHashNotEmptyBackgroundContext)
}

func TestHashCorrectCostUsed(t *testing.T) {
	const expectedCost = 10
	service := bcryptService.NewBcrypt(expectedCost)
	password := "testPassword123"
	ctx := context.Background()

	hash, err := service.Hash(ctx, password)

	require.NoError(t, err, msgNoErrorValidPassword)

	actualCost, err := cryptobcrypt.Cost([]byte(hash))
	require.NoError(t, err, msgNoErrorExtractingCost)
	assert.Equal(t, expectedCost, actualCost, msgCostMatchesExpected)
}

const (
	msgServiceNotNil             = "service should not be nil"
	msgImplementsPasswordService = "service should implement password service interface"
	msgNoErrorHashing            = "should not return error when hashing"
	msgNoErrorGettingCost        = "should not return error when getting cost"
	msgCostMatchesExpected       = "cost in hash should match expected value"
	msgUsesDefaultCostForLow     = "should use default cost when cost is below minimum"
)

func TestNew1(t *testing.T) {
	tests := []struct {
		name     string
		cost     int
		wantCost int
	}{
		{
			name:     "valid cost value",
			cost:     10,
			wantCost: 10,
		},
		{
			name:     "minimum cost value",
			cost:     cryptobcrypt.MinCost,
			wantCost: cryptobcrypt.MinCost,
		},
		{
			name:     "cost below minimum",
			cost:     cryptobcrypt.MinCost - 1,
			wantCost: cryptobcrypt.DefaultCost,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := bcryptService.NewBcrypt(tt.cost)

			assert.NotNil(t, service, msgServiceNotNil)
			assert.Implements(t, (*svc.PasswordService)(nil), service, msgImplementsPasswordService)
		})
	}
}

func TestNew_UsesCorrectCost(t *testing.T) {
	cost := 10
	service := bcryptService.NewBcrypt(cost)

	password := "testPassword123"
	ctx := context.Background()
	hash, err := service.Hash(ctx, password)

	require.NoError(t, err, msgNoErrorHashing)

	hashInfo, err := cryptobcrypt.Cost([]byte(hash))
	require.NoError(t, err, msgNoErrorGettingCost)
	assert.Equal(t, cost, hashInfo, msgCostMatchesExpected)
}

func TestNew_AdjustsLowCost(t *testing.T) {
	service := bcryptService.NewBcrypt(cryptobcrypt.MinCost - 1)

	password := "testPassword123"
	ctx := context.Background()
	hash, err := service.Hash(ctx, password)

	require.NoError(t, err, msgNoErrorHashing)

	hashInfo, err := cryptobcrypt.Cost([]byte(hash))
	require.NoError(t, err, msgNoErrorGettingCost)
	assert.Equal(t, cryptobcrypt.DefaultCost, hashInfo, msgUsesDefaultCostForLow)
}

//nolint:gosec
const (
	msgVerifySuccess             = "should successfully verify correct password"
	msgVerifyFail                = "should return false for wrong password without error"
	msgVerifyEmptyPassword       = "should return error for empty password"
	msgVerifyEmptyHash           = "should return error for empty hash"
	msgResultFalseWithError      = "result should be false with error"
	msgVerifyInvalidHash         = "should return error for invalid hash"
	msgResultFalseForInvalidHash = "result should be false for invalid hash"
	msgErrorContainsExpectedText = "error message should contain expected text"
	msgContextIgnored            = "result should not depend on context"
	msgNoErrorCreatingHash       = "should not return error when creating hash"
	msgErrorNotMismatchedHash    = "error should not be err mismatched hash and password"
	msgNoErrorWrongPassword      = "should not return error for wrong password"
	msgResultFalseWrongPassword  = "result should be false for wrong password"
)

func TestVerifySuccess(t *testing.T) {
	service := bcryptService.NewBcrypt(10)
	password := "validPassword123"
	ctx := context.Background()

	hash, err := service.Hash(ctx, password)
	require.NoError(t, err, msgNoErrorCreatingHash)

	result, err := service.Verify(ctx, password, hash)

	require.NoError(t, err, msgVerifySuccess)
	assert.True(t, result, msgVerifySuccess)
}

func TestVerifyWrongPassword(t *testing.T) {
	service := bcryptService.NewBcrypt(10)
	password := "validPassword123"
	wrongPassword := "wrongPassword123"
	ctx := context.Background()

	hash, err := service.Hash(ctx, password)
	require.NoError(t, err, msgNoErrorCreatingHash)

	result, err := service.Verify(ctx, wrongPassword, hash)

	require.NoError(t, err, msgVerifyFail)
	assert.False(t, result, msgVerifyFail)
}

func TestVerifyEmptyPassword(t *testing.T) {
	service := bcryptService.NewBcrypt(10)
	hash := "$2a$10$NlNRwS5q6Iei4VxwXSZ5c.4XJSmLn2A.u8VIgQP94HXVDhkFD/Csa"
	ctx := context.Background()

	result, err := service.Verify(ctx, "", hash)

	require.Error(t, err, msgVerifyEmptyPassword)
	assert.False(t, result, msgResultFalseWithError)
	assert.ErrorIs(t, err, domainservices.ErrInvalidPassword, msgErrorInvalidPassword)
}

func TestVerifyEmptyHash(t *testing.T) {
	service := bcryptService.NewBcrypt(10)
	password := "validPassword123"
	ctx := context.Background()

	result, err := service.Verify(ctx, password, "")

	require.Error(t, err, msgVerifyEmptyHash)
	assert.False(t, result, msgResultFalseWithError)
	assert.ErrorIs(t, err, domainservices.ErrInvalidPassword, msgErrorInvalidPassword)
}

func Test_verify_invalid_hash(t *testing.T) {
	service := bcryptService.NewBcrypt(10)
	password := "validPassword123"
	invalidHash := "invalid_hash_format"
	ctx := context.Background()

	result, err := service.Verify(ctx, password, invalidHash)

	require.Error(t, err, msgVerifyInvalidHash)
	assert.False(t, result, msgResultFalseForInvalidHash)
	require.NotErrorIs(t, err, cryptobcrypt.ErrMismatchedHashAndPassword, msgErrorNotMismatchedHash)
	assert.Contains(t, err.Error(), "error comparing password with hash", msgErrorContainsExpectedText)
}

func TestVerifyContextIgnored(t *testing.T) {
	service := bcryptService.NewBcrypt(10)
	password := "validPassword123"
	ctx := context.Background()

	hash, err := service.Hash(ctx, password)
	require.NoError(t, err, msgNoErrorCreatingHash)

	nilCtx := context.Context(nil)
	bgCtx := context.Background()

	result1, err1 := service.Verify(nilCtx, password, hash)
	result2, err2 := service.Verify(bgCtx, password, hash)

	assert.NoError(t, err1, msgNoErrorNilContext)
	assert.NoError(t, err2, msgNoErrorBackgroundContext)
	assert.True(t, result1, msgNoErrorNilContext)
	assert.True(t, result2, msgNoErrorBackgroundContext)
	assert.Equal(t, result1, result2, msgContextIgnored)
}

func TestVerifyNilContextWrongPassword(t *testing.T) {
	service := bcryptService.NewBcrypt(10)
	password := "validPassword123"
	wrongPassword := "wrongPassword123"
	ctx := context.Background()

	hash, err := service.Hash(ctx, password)
	require.NoError(t, err, msgNoErrorCreatingHash)

	nilCtx := context.Context(nil)
	result, err := service.Verify(nilCtx, wrongPassword, hash)

	require.NoError(t, err, msgNoErrorWrongPassword)
	assert.False(t, result, msgResultFalseWrongPassword)
}

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
		domainClaims      domainservices.JWTClaims
		expectedUserID    string
		expectedSubject   string
		expectedUsername  string
		expectedExpiresAt time.Time
		expectedIssuedAt  time.Time
	}{
		{
			name: "all fields filled",
			domainClaims: domainservices.JWTClaims{
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
			domainClaims: domainservices.JWTClaims{
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
			domainClaims: domainservices.JWTClaims{
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

		domainClaims := domainservices.JWTClaims{
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

		domainClaims := domainservices.JWTClaims{
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

		domainClaims := domainservices.JWTClaims{
			UserID:    complexUserID,
			Username:  "complexuser",
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}

		jwtClaims := jwtService.GetDomainToJWTClaimsForTest(domainClaims)

		assert.Equal(t, complexUserID, jwtClaims.Subject, msgSubjectMatchesComplexID)
	})
}

var errInvalidSigningAlgorithm = errors.New("invalid signing algorithm")

//nolint:gosec
const (
	msgTokenFormatValid         = "token should have valid JWT format"
	msgTokenSignatureValid      = "token signature should be valid"
	msgExpiryTimeCorrect        = "token expiration time should match expected"
	msgErrorOnEmptySecretKey    = "should return error with empty secret key"
	msgErrorTypeCheck           = "error type should match expected"
	msgUserIDInTokenCorrect     = "user ID in token should match provided value"
	msgUsernameInTokenCorrect   = "username in token should match provided value"
	msgIssuedAtTimeCorrect      = "token issued at time should be approximately current"
	msgSubjectMatchesUserID     = "token subject should match user ID"
	msgNoErrorGeneratingToken   = "should not return errors when generating token"
	msgTokenNotEmpty            = "token should not be empty"
	msgNoErrorWithEmptyUsername = "should not return errors when generating token with empty username"
	msgTokenEmptyOnError        = "token should be empty on error"
	msgExpiryZeroOnError        = "expiration time should be zero on error"
	msgNoErrorWithNegativeTTL   = "should generate token even with negative TTL"
	msgExpiryInPast             = "expiration time should be in the past"
	msgErrorOnExpiredToken      = "should return error when validating expired token"
	msgExpiredTokenError        = "should return expired token error"
	msgNoErrorWithLongTTL       = "should not return errors when generating token with long TTL"
	msgErrorOnInvalidSignature  = "should return error with invalid signature"
	msgTokenGenerationError     = "should return token generation error"
	msgErrorCreatingTestLogger  = "error creating test logger"
	msgExtractClaimsFromToken   = "should be able to extract claims from token"
	msgExpiresAtPresentInToken  = "expires at should be present in token"
	msgIssuedAtPresentInToken   = "issued at should be present in token"
	msgInvalidSigningAlgorithm  = "invalid signing algorithm"
)

func TestGenerateAccessToken(t *testing.T) {
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err, msgErrorCreatingTestLogger)

	ctx := context.Background()
	ctx = logger.NewContext(ctx, testLogger)

	t.Run("successful token generation with valid parameters", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		accessTTL := 15 * time.Minute
		userID := "test-user-id-123"
		username := "testuser"

		service := jwtService.NewJWT(secretKey, accessTTL, 24*time.Hour)

		token, expiryTime, err := service.GenerateAccessToken(ctx, userID, username)

		require.NoError(t, err, msgNoErrorGeneratingToken)
		assert.NotEmpty(t, token, msgTokenNotEmpty)

		expectedExpiry := time.Now().Add(accessTTL)
		assert.WithinDuration(t, expectedExpiry, expiryTime, 2*time.Second, msgExpiryTimeCorrect)

		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("%w: %s", errInvalidSigningAlgorithm, msgInvalidSigningAlgorithm)
			}
			return []byte(secretKey), nil
		})

		require.NoError(t, err, msgTokenSignatureValid)
		assert.True(t, parsedToken.Valid, msgTokenFormatValid)

		claims, ok := parsedToken.Claims.(jwt.MapClaims)
		require.True(t, ok, msgExtractClaimsFromToken)

		assert.Equal(t, userID, claims["user_id"], msgUserIDInTokenCorrect)
		assert.Equal(t, username, claims["username"], msgUsernameInTokenCorrect)
		assert.Equal(t, userID, claims["sub"], msgSubjectMatchesUserID)

		issuedAt, ok := claims["iat"].(float64)
		require.True(t, ok, msgIssuedAtPresentInToken)

		issuedAtTime := time.Unix(int64(issuedAt), 0)
		assert.WithinDuration(t, time.Now(), issuedAtTime, 2*time.Second, msgIssuedAtTimeCorrect)

		expiresAt, ok := claims["exp"].(float64)
		require.True(t, ok, msgExpiresAtPresentInToken)

		expiresAtTime := time.Unix(int64(expiresAt), 0)
		assert.WithinDuration(t, expiryTime, expiresAtTime, 1*time.Second, msgExpiryTimeCorrect)
	})

	t.Run("token generation with empty username", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		accessTTL := 15 * time.Minute
		userID := "test-user-id-456"
		username := ""

		service := jwtService.NewJWT(secretKey, accessTTL, 24*time.Hour)

		token, expiryTime, err := service.GenerateAccessToken(ctx, userID, username)

		require.NoError(t, err, msgNoErrorWithEmptyUsername)
		assert.NotEmpty(t, token, msgTokenNotEmpty)

		parsedToken, err := jwt.Parse(token, func(_ *jwt.Token) (interface{}, error) {
			return []byte(secretKey), nil
		})

		require.NoError(t, err, msgTokenSignatureValid)

		claims, ok := parsedToken.Claims.(jwt.MapClaims)
		require.True(t, ok, msgExtractClaimsFromToken)

		assert.Equal(t, userID, claims["user_id"], msgUserIDInTokenCorrect)
		assert.Equal(t, username, claims["username"], msgUsernameInTokenCorrect)

		expectedExpiry := time.Now().Add(accessTTL)
		assert.WithinDuration(t, expectedExpiry, expiryTime, 2*time.Second, msgExpiryTimeCorrect)
	})

	t.Run("error with empty secret key", func(t *testing.T) {
		emptySecretKey := ""
		accessTTL := 15 * time.Minute
		userID := "test-user-id-789"
		username := "testuser"

		service := jwtService.NewJWT(emptySecretKey, accessTTL, 24*time.Hour)

		token, expiryTime, err := service.GenerateAccessToken(ctx, userID, username)

		require.Error(t, err, msgErrorOnEmptySecretKey)
		require.ErrorIs(t, err, domainservices.ErrGeneratingJWTToken, msgErrorTypeCheck)
		assert.Empty(t, token, msgTokenEmptyOnError)
		assert.True(t, expiryTime.IsZero(), msgExpiryZeroOnError)
	})

	t.Run("token with expired ttl", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		accessTTL := -15 * time.Minute
		userID := "test-user-id-expired"
		username := "expireduser"

		service := jwtService.NewJWT(secretKey, accessTTL, 24*time.Hour)

		token, expiryTime, err := service.GenerateAccessToken(ctx, userID, username)

		require.NoError(t, err, msgNoErrorWithNegativeTTL)
		assert.NotEmpty(t, token, msgTokenNotEmpty)

		assert.True(t, expiryTime.Before(time.Now()), msgExpiryInPast)

		_, err = service.ValidateAccessToken(ctx, token)
		require.Error(t, err, msgErrorOnExpiredToken)
		assert.ErrorIs(t, err, domainservices.ErrExpiredJWTToken, msgExpiredTokenError)
	})

	t.Run("long ttl validation", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		accessTTL := 8760 * time.Hour
		userID := "test-user-id-long"
		username := "longuser"

		service := jwtService.NewJWT(secretKey, accessTTL, 24*time.Hour)

		token, expiryTime, err := service.GenerateAccessToken(ctx, userID, username)

		require.NoError(t, err, msgNoErrorWithLongTTL)
		assert.NotEmpty(t, token, msgTokenNotEmpty)

		expectedExpiry := time.Now().Add(accessTTL)
		assert.WithinDuration(t, expectedExpiry, expiryTime, 2*time.Second, msgExpiryTimeCorrect)
	})
}

func TestGenerateAccessTokenWithLogger(t *testing.T) {
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err, msgErrorCreatingTestLogger)

	ctx := context.Background()
	ctx = logger.NewContext(ctx, testLogger)

	t.Run("logging token signature error", func(t *testing.T) {
		emptySecretKey := ""
		accessTTL := 15 * time.Minute
		userID := "test-user-id-error"
		username := "erroruser"

		service := jwtService.NewJWT(emptySecretKey, accessTTL, 24*time.Hour)

		_, _, err := service.GenerateAccessToken(ctx, userID, username)

		require.Error(t, err, msgErrorOnInvalidSignature)
		assert.ErrorIs(t, err, domainservices.ErrGeneratingJWTToken, msgTokenGenerationError)
	})
}

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
		farFuture := now.Add(10 * 365 * 24 * time.Hour).Truncate(time.Second)

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

const (
	msgGenerateAccessTokenNoError  = "should generate access token without errors"
	msgAccessTokenNotEmpty         = "access token should not be empty"
	msgAccessTokenExpiry           = "access token expiry should be approximately current time + accessTTL"
	msgGenerateRefreshTokenNoError = "should generate refresh token without errors"
	msgRefreshTokenNotEmpty        = "refresh token should not be empty"
	msgRefreshTokenExpiry          = "refresh token expiry should be approximately current time + refreshTTL"
	msgValidAccessTokenNoError     = "valid access token should not cause error"
	msgUserIDMatch                 = "user ID should match the original"
)

func TestNew(t *testing.T) {
	testCases := []struct {
		name            string
		secretKey       string
		accessTokenTTL  time.Duration
		refreshTokenTTL time.Duration
	}{
		{
			name:            "with basic settings",
			secretKey:       "test-secret-key",
			accessTokenTTL:  15 * time.Minute,
			refreshTokenTTL: 24 * time.Hour,
		},
		{
			name:            "with empty key and zero TTL",
			secretKey:       "",
			accessTokenTTL:  0,
			refreshTokenTTL: 0,
		},
		{
			name:            "with very long key and large TTL",
			secretKey:       "very-long-secret-key-for-testing-purposes-123456789012345678901234567890",
			accessTokenTTL:  720 * time.Hour,
			refreshTokenTTL: 8760 * time.Hour,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service := jwtService.NewJWT(tc.secretKey, tc.accessTokenTTL, tc.refreshTokenTTL)

			assert.Implements(t, (*svc.TokenService)(nil), service)
		})
	}
}

func TestNewServiceFunctionality(t *testing.T) {
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err, "error creating test logger")

	ctx := context.Background()
	ctx = logger.NewContext(ctx, testLogger)
	// #nosec G101
	secretKey := "test-jwt_service-key"
	accessTTL := 15 * time.Minute
	refreshTTL := 24 * time.Hour
	userID := "test-user-123"
	username := "testuser"

	service := jwtService.NewJWT(secretKey, accessTTL, refreshTTL)

	accessToken, accessExpiry, err := service.GenerateAccessToken(ctx, userID, username)
	require.NoError(t, err, msgGenerateAccessTokenNoError)
	assert.NotEmpty(t, accessToken, msgAccessTokenNotEmpty)

	expectedAccessExpiry := time.Now().Add(accessTTL)
	assert.WithinDuration(t, expectedAccessExpiry, accessExpiry, 2*time.Second, msgAccessTokenExpiry)

	refreshToken, refreshExpiry, err := service.GenerateRefreshToken(ctx, userID)
	require.NoError(t, err, msgGenerateRefreshTokenNoError)
	assert.NotEmpty(t, refreshToken, msgRefreshTokenNotEmpty)

	expectedRefreshExpiry := time.Now().Add(refreshTTL)
	assert.WithinDuration(t, expectedRefreshExpiry, refreshExpiry, 2*time.Second, msgRefreshTokenExpiry)

	validatedUserID, err := service.ValidateAccessToken(ctx, accessToken)
	require.NoError(t, err, msgValidAccessTokenNoError)
	assert.Equal(t, userID, validatedUserID, msgUserIDMatch)
}

//nolint:gosec
const (
	msgNoErrorValidatingToken       = "should validate token without errors"
	msgInvalidTokenFormat           = "should return invalid token error for bad format"
	msgInvalidTokenReturnedError    = "invalid token should return error"
	msgCorrectUserIDReturned        = "should return correct user ID"
	msgExpiredTokenReturnsError     = "expired token should return error"
	msgCreateTokenWithNoneAlgorithm = "should create token with none algorithm"
	msgCreateTokenWithCustomClaims  = "should create token with custom claims"
)

func TestValidateAccessToken(t *testing.T) {
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err, msgErrorCreatingTestLogger)

	ctx := context.Background()
	ctx = logger.NewContext(ctx, testLogger)

	t.Run("successful validation of a valid token", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		accessTTL := 15 * time.Minute
		userID := "test-user-id-123"
		username := "testuser"

		service := jwtService.NewJWT(secretKey, accessTTL, 24*time.Hour)

		token, _, err := service.GenerateAccessToken(ctx, userID, username)
		require.NoError(t, err, msgNoErrorGeneratingToken)
		assert.NotEmpty(t, token, msgTokenNotEmpty)

		resultUserID, err := service.ValidateAccessToken(ctx, token)
		require.NoError(t, err, msgNoErrorValidatingToken)
		assert.Equal(t, userID, resultUserID, msgCorrectUserIDReturned)
	})

	t.Run("error on expired token", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		accessTTL := -15 * time.Minute
		userID := "test-user-id-123"
		username := "testuser"

		service := jwtService.NewJWT(secretKey, accessTTL, 24*time.Hour)

		token, _, err := service.GenerateAccessToken(ctx, userID, username)
		require.NoError(t, err, msgNoErrorGeneratingToken)

		_, err = service.ValidateAccessToken(ctx, token)
		require.Error(t, err, msgExpiredTokenReturnsError)
		assert.ErrorIs(t, err, domainservices.ErrExpiredJWTToken, msgExpiredTokenError)
	})

	t.Run("error on invalid token format", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		service := jwtService.NewJWT(secretKey, 15*time.Minute, 24*time.Hour)

		invalidToken := "invalid.token.format"

		_, err := service.ValidateAccessToken(ctx, invalidToken)
		require.Error(t, err, msgInvalidTokenReturnedError)
		assert.ErrorIs(t, err, domainservices.ErrInvalidJWTToken, msgInvalidTokenFormat)
	})

	t.Run("error on token with wrong signature", func(t *testing.T) {
		secretKey1 := "test-secret-key-12345"
		secretKey2 := "different-secret-key-67890"
		accessTTL := 15 * time.Minute
		userID := "test-user-id-123"
		username := "testuser"

		service1 := jwtService.NewJWT(secretKey1, accessTTL, 24*time.Hour)
		service2 := jwtService.NewJWT(secretKey2, accessTTL, 24*time.Hour)

		token, _, err := service1.GenerateAccessToken(ctx, userID, username)
		require.NoError(t, err, msgNoErrorGeneratingToken)

		_, err = service2.ValidateAccessToken(ctx, token)
		require.Error(t, err, msgInvalidTokenReturnedError)
		assert.ErrorIs(t, err, domainservices.ErrInvalidJWTToken, msgInvalidTokenFormat)
	})

	t.Run("error on token with invalid signing method", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		userID := "test-user-id-123"

		claims := &services.Claims{
			UserID:   userID,
			Username: "testuser",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Subject:   userID,
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err, msgCreateTokenWithNoneAlgorithm)

		service := jwtService.NewJWT(secretKey, 15*time.Minute, 24*time.Hour)
		_, err = service.ValidateAccessToken(ctx, tokenString)
		require.Error(t, err, msgInvalidTokenReturnedError)
		assert.ErrorIs(t, err, domainservices.ErrInvalidJWTToken, msgInvalidTokenFormat)
	})

	t.Run("error on empty token", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		service := jwtService.NewJWT(secretKey, 15*time.Minute, 24*time.Hour)

		emptyToken := ""
		_, err := service.ValidateAccessToken(ctx, emptyToken)
		require.Error(t, err, msgInvalidTokenReturnedError)
		assert.ErrorIs(t, err, domainservices.ErrInvalidJWTToken, msgInvalidTokenFormat)
	})

	t.Run("token with invalid claims", func(t *testing.T) {
		secretKey := "test-secret-key-12345"

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"some_random_field": "not_user_id",
		})

		tokenString, err := token.SignedString([]byte(secretKey))
		require.NoError(t, err, msgCreateTokenWithCustomClaims)

		service := jwtService.NewJWT(secretKey, 15*time.Minute, 24*time.Hour)
		_, err = service.ValidateAccessToken(ctx, tokenString)
		require.Error(t, err, msgInvalidTokenReturnedError)
		assert.ErrorIs(t, err, domainservices.ErrInvalidJWTToken, msgInvalidTokenFormat)
	})
}

const (
	defaultJWTSecretKey     = "test-secret-key"
	defaultAccessTokenTTL   = 15 * time.Minute
	defaultRefreshTokenTTL  = 24 * time.Hour
	defaultBcryptCost       = 10
	errMsgServiceInitFailed = "service factory should properly initialize services"
	errMsgFactoryNotNil     = "service factory should not be nil"
	errMsgPasswordSvcNotNil = "password service should not be nil"
	errMsgTokenSvcNotNil    = "token service should not be nil"
)

func Test_NewServiceFactory(t *testing.T) {
	factory := services.NewServiceFactory(
		defaultJWTSecretKey,
		defaultAccessTokenTTL,
		defaultRefreshTokenTTL,
		defaultBcryptCost,
	)

	assert.NotNil(t, factory, errMsgFactoryNotNil)
	assert.NotNil(t, factory.PasswordService(), errMsgPasswordSvcNotNil)
	assert.NotNil(t, factory.TokenService(), errMsgTokenSvcNotNil)

	passwordService := factory.PasswordService()
	tokenService := factory.TokenService()

	assert.IsType(t, &services.ServiceBcrypt{}, passwordService, errMsgServiceInitFailed)
	assert.IsType(t, &services.ServiceJWT{}, tokenService, errMsgServiceInitFailed)

	// Verify interface implementation
	assert.Implements(t, (*ports.PasswordService)(nil), passwordService, errMsgServiceInitFailed)
	assert.Implements(t, (*ports.TokenService)(nil), tokenService, errMsgServiceInitFailed)
}

func Test_NewServiceFactory_WithMinimalBcryptCost(t *testing.T) {
	factory := services.NewServiceFactory(
		defaultJWTSecretKey,
		defaultAccessTokenTTL,
		defaultRefreshTokenTTL,
		bcrypt.MinCost-1,
	)

	assert.NotNil(t, factory, errMsgFactoryNotNil)
	assert.NotNil(t, factory.PasswordService(), errMsgPasswordSvcNotNil)
}

func Test_NewServiceFactory_WithEmptyJWTKey(t *testing.T) {
	factory := services.NewServiceFactory(
		"",
		defaultAccessTokenTTL,
		defaultRefreshTokenTTL,
		defaultBcryptCost,
	)

	assert.NotNil(t, factory, errMsgFactoryNotNil)
	assert.NotNil(t, factory.TokenService(), errMsgTokenSvcNotNil)
}

func Test_NewServiceFactory_WithZeroDurations(t *testing.T) {
	factory := services.NewServiceFactory(
		defaultJWTSecretKey,
		0,
		0,
		defaultBcryptCost,
	)

	assert.NotNil(t, factory, errMsgFactoryNotNil)
	assert.NotNil(t, factory.TokenService(), errMsgTokenSvcNotNil)
}

const (
	errMsgSvcShouldNotNil = "password service should not be nil"
	errMsgShouldBeService = "returned service should be of correct type"
	errMsgShouldBeTheSame = "should return the same service instance on multiple calls"
)

func TestServiceFactory_PasswordService(t *testing.T) {
	t.Run("returns non-nil password service", func(t *testing.T) {
		factory := services.NewServiceFactory(
			defaultJWTSecretKey,
			defaultAccessTokenTTL,
			defaultRefreshTokenTTL,
			defaultBcryptCost,
		)

		passwordService := factory.PasswordService()

		require.NotNil(t, passwordService, errMsgSvcShouldNotNil)
		assert.IsType(t, &services.ServiceBcrypt{}, passwordService, errMsgShouldBeService)
		assert.Implements(t, (*ports.PasswordService)(nil), passwordService, errMsgShouldBeService)
	})

	t.Run("returns same instance on multiple calls", func(t *testing.T) {
		factory := services.NewServiceFactory(
			defaultJWTSecretKey,
			defaultAccessTokenTTL,
			defaultRefreshTokenTTL,
			defaultBcryptCost,
		)

		service1 := factory.PasswordService()
		service2 := factory.PasswordService()

		assert.Same(t, service1, service2, errMsgShouldBeTheSame)
	})

	t.Run("with minimal bcrypt cost", func(t *testing.T) {
		factory := services.NewServiceFactory(
			defaultJWTSecretKey,
			defaultAccessTokenTTL,
			defaultRefreshTokenTTL,
			bcrypt.MinCost-1,
		)

		passwordService := factory.PasswordService()

		require.NotNil(t, passwordService, errMsgSvcShouldNotNil)
		assert.IsType(t, &services.ServiceBcrypt{}, passwordService, errMsgShouldBeService)
		assert.Implements(t, (*ports.PasswordService)(nil), passwordService, errMsgShouldBeService)
	})
}

const (
	msgTokenServiceShouldNotBeNil = "token service should not be nil"
	msgShouldBeCorrectType        = "returned service should be of correct type"
	msgShouldReturnSameInstance   = "should return the same service instance on multiple calls"
	msgShouldNotBeNilWithEmptyKey = "token service should not be nil even with empty key"
	msgShouldNotBeNilWithZeroTTL  = "token service should not be nil even with zero TTL"
)

func TestServiceFactory_TokenService(t *testing.T) {
	t.Run("returns non-nil token service", func(t *testing.T) {
		factory := services.NewServiceFactory(
			defaultJWTSecretKey,
			defaultAccessTokenTTL,
			defaultRefreshTokenTTL,
			defaultBcryptCost,
		)

		tokenService := factory.TokenService()

		require.NotNil(t, tokenService, msgTokenServiceShouldNotBeNil)
		assert.IsType(t, &services.ServiceJWT{}, tokenService, msgShouldBeCorrectType)
		assert.Implements(t, (*ports.TokenService)(nil), tokenService, msgShouldBeCorrectType)
	})

	t.Run("returns same instance on multiple calls", func(t *testing.T) {
		factory := services.NewServiceFactory(
			defaultJWTSecretKey,
			defaultAccessTokenTTL,
			defaultRefreshTokenTTL,
			defaultBcryptCost,
		)

		service1 := factory.TokenService()
		service2 := factory.TokenService()

		assert.Same(t, service1, service2, msgShouldReturnSameInstance)
	})

	t.Run("with empty secret key", func(t *testing.T) {
		factory := services.NewServiceFactory(
			"", // empty secret key
			defaultAccessTokenTTL,
			defaultRefreshTokenTTL,
			defaultBcryptCost,
		)

		tokenService := factory.TokenService()

		require.NotNil(t, tokenService, msgShouldNotBeNilWithEmptyKey)
		assert.IsType(t, &services.ServiceJWT{}, tokenService, msgShouldBeCorrectType)
		assert.Implements(t, (*ports.TokenService)(nil), tokenService, msgShouldBeCorrectType)
	})

	t.Run("with zero token ttl", func(t *testing.T) {
		factory := services.NewServiceFactory(
			defaultJWTSecretKey,
			0, // zero TTL for access token
			0, // zero TTL for refresh token
			defaultBcryptCost,
		)

		tokenService := factory.TokenService()

		require.NotNil(t, tokenService, msgShouldNotBeNilWithZeroTTL)
		assert.IsType(t, &services.ServiceJWT{}, tokenService, msgShouldBeCorrectType)
		assert.Implements(t, (*ports.TokenService)(nil), tokenService, msgShouldBeCorrectType)
	})
}
