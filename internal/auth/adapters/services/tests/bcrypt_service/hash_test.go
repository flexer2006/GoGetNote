package bcrypt_service_test

import (
	"context"
	"github.com/stretchr/testify/require"
	services2 "gogetnote/internal/auth/adapters/services"
	"testing"

	"github.com/stretchr/testify/assert"
	cryptobcrypt "golang.org/x/crypto/bcrypt"

	"gogetnote/internal/auth/domain/services"
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
	service := services2.NewBcrypt(10)
	validPassword := "validPassword123"
	ctx := context.Background()

	hash, err := service.Hash(ctx, validPassword)

	require.NoError(t, err, msgNoErrorValidPassword)
	assert.NotEmpty(t, hash, msgHashNotEmpty)

	err = cryptobcrypt.CompareHashAndPassword([]byte(hash), []byte(validPassword))
	assert.NoError(t, err, msgHashVerifiable)
}

func TestHashEmptyPassword(t *testing.T) {
	service := services2.NewBcrypt(10)
	emptyPassword := ""
	ctx := context.Background()

	hash, err := service.Hash(ctx, emptyPassword)

	require.Error(t, err, msgEmptyPasswordError)
	assert.Empty(t, hash, msgHashEmptyInvalidPassword)
	assert.ErrorIs(t, err, services.ErrInvalidPassword, msgErrorInvalidPassword)
}

func TestHashShortPassword(t *testing.T) {
	service := services2.NewBcrypt(10)

	shortPassword := "short"
	ctx := context.Background()

	hash, err := service.Hash(ctx, shortPassword)

	require.Error(t, err, msgShortPasswordError)
	assert.Empty(t, hash, msgHashEmptyShortPassword)
	require.ErrorIs(t, err, services.ErrInvalidPassword, msgErrorInvalidPassword)
}

func TestHashDifferentPasswordsDifferentHashes(t *testing.T) {
	service := services2.NewBcrypt(10)
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
	service := services2.NewBcrypt(10)
	password := "samePassword123"
	ctx := context.Background()

	hash1, err1 := service.Hash(ctx, password)
	hash2, err2 := service.Hash(ctx, password)

	assert.NoError(t, err1, msgNoErrorFirstHash)
	assert.NoError(t, err2, msgNoErrorSecondHash)
	assert.NotEqual(t, hash1, hash2, msgDifferentHashesSamePassword)
}

func TestHashContextIgnored(t *testing.T) {
	service := services2.NewBcrypt(10)
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
	service := services2.NewBcrypt(expectedCost)
	password := "testPassword123"
	ctx := context.Background()

	hash, err := service.Hash(ctx, password)

	require.NoError(t, err, msgNoErrorValidPassword)

	actualCost, err := cryptobcrypt.Cost([]byte(hash))
	require.NoError(t, err, msgNoErrorExtractingCost)
	assert.Equal(t, expectedCost, actualCost, msgCostMatchesExpected)
}
