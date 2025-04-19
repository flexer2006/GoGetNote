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
	service := services2.NewBcrypt(10)
	password := "validPassword123"
	ctx := context.Background()

	hash, err := service.Hash(ctx, password)
	require.NoError(t, err, msgNoErrorCreatingHash)

	result, err := service.Verify(ctx, password, hash)

	require.NoError(t, err, msgVerifySuccess)
	assert.True(t, result, msgVerifySuccess)
}

func TestVerifyWrongPassword(t *testing.T) {
	service := services2.NewBcrypt(10)
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
	service := services2.NewBcrypt(10)
	hash := "$2a$10$NlNRwS5q6Iei4VxwXSZ5c.4XJSmLn2A.u8VIgQP94HXVDhkFD/Csa"
	ctx := context.Background()

	result, err := service.Verify(ctx, "", hash)

	require.Error(t, err, msgVerifyEmptyPassword)
	assert.False(t, result, msgResultFalseWithError)
	assert.ErrorIs(t, err, services.ErrInvalidPassword, msgErrorInvalidPassword)
}

func TestVerifyEmptyHash(t *testing.T) {
	service := services2.NewBcrypt(10)
	password := "validPassword123"
	ctx := context.Background()

	result, err := service.Verify(ctx, password, "")

	require.Error(t, err, msgVerifyEmptyHash)
	assert.False(t, result, msgResultFalseWithError)
	assert.ErrorIs(t, err, services.ErrInvalidPassword, msgErrorInvalidPassword)
}

func Test_verify_invalid_hash(t *testing.T) {
	service := services2.NewBcrypt(10)
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
	service := services2.NewBcrypt(10)
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
	service := services2.NewBcrypt(10)
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
