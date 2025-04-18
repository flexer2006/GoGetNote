package app

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"gogetnote/internal/auth/domain/entities"
	"gogetnote/internal/auth/domain/services"
	"gogetnote/internal/auth/ports/api"
	"gogetnote/internal/auth/ports/repositories"
	svc "gogetnote/internal/auth/ports/services"
	"gogetnote/pkg/logger"

	"go.uber.org/zap"
)

const (
	methodRegister       = "Register"
	methodLogin          = "Login"
	methodRefreshTokens  = "RefreshTokens"
	methodLogout         = "Logout"
	methodGenerateTokens = "generateTokenPair"

	msgStartRegistration    = "starting user registration"
	msgInvalidEmailFormat   = "invalid email format"
	msgEmptyUsername        = "empty username provided"
	msgInvalidPassword      = "invalid password"
	msgEmailExists          = "user with this email already exists"
	msgUserRegistered       = "user registered successfully"
	msgTokensGenerated      = "authentication tokens generated for new user"
	msgLoginAttempt         = "login attempt"
	msgLoginNonExistent     = "login attempt with non-existent email"
	msgInvalidPasswordAuth  = "invalid password provided"
	msgUserLoggedIn         = "user logged in successfully"
	msgTokensGeneratedLogin = "authentication tokens generated for user"
	msgRefreshingTokens     = "refreshing tokens"
	msgRevokedTokenAttempt  = "attempt to use revoked token"
	msgOldTokenRevoked      = "old token revoked successfully"
	msgTokensRefreshed      = "tokens refreshed successfully"
	msgProcessingLogout     = "processing logout request"
	msgUserLoggedOut        = "user logged out successfully"
	msgTokenPairGenerated   = "token pair generated successfully"

	msgErrCheckExistingUser     = "failed to check existing user"
	msgErrHashPassword          = "failed to hash password"
	msgErrCreateUser            = "failed to create user"
	msgErrGenerateTokens        = "failed to generate tokens for new user"
	msgErrFindingUser           = "error finding user by email"
	msgErrVerifyingPassword     = "error verifying password"
	msgErrGenerateLoginTokens   = "failed to generate tokens on login"
	msgErrInvalidRefreshToken   = "invalid refresh token"
	msgErrFindingUserForToken   = "failed to find user for refresh token"
	msgErrRevokingOldToken      = "failed to revoke old token"
	msgErrGenerateRefreshTokens = "failed to generate new tokens during refresh"
	msgErrRevokingRefreshToken  = "failed to revoke refresh token"
	msgErrGenerateAccessToken   = "failed to generate access token"
	msgErrGenerateRefreshToken  = "failed to generate refresh token"
	msgErrStoreRefreshToken     = "failed to store refresh token"

	errCtxValidatingEmail        = "validating email"
	errCtxValidatingUsername     = "validating username"
	errCtxValidatingPassword     = "validating password"
	errCtxCheckingUser           = "checking existing user"
	errCtxEmailRegistered        = "email already registered"
	errCtxHashingPassword        = "hashing password"
	errCtxCreatingUser           = "creating user"
	errCtxGeneratingTokens       = "generating tokens"
	errCtxInvalidCredentials     = "invalid credentials"
	errCtxFindingUser            = "finding user"
	errCtxVerifyingPassword      = "verifying password"
	errCtxFindingRefreshToken    = "finding refresh token"
	errCtxTokenRevoked           = "token revoked"
	errCtxRevokingOldToken       = "revoking old token"
	errCtxGeneratingNewTokens    = "generating new tokens"
	errCtxRevokingToken          = "revoking token"
	errCtxGeneratingAccessToken  = "generating access token"
	errCtxGeneratingRefreshToken = "generating refresh token"
	errCtxStoringRefreshToken    = "storing refresh token"
)

// AuthUseCaseImpl реализует интерфейс AuthUseCase.
type AuthUseCaseImpl struct {
	userRepo    repositories.UserRepository
	tokenRepo   repositories.TokenRepository
	passwordSvc svc.PasswordService
	tokenSvc    svc.TokenService
}

// NewAuthUseCase создает новый экземпляр сервиса аутентификации.
func NewAuthUseCase(
	userRepo repositories.UserRepository,
	tokenRepo repositories.TokenRepository,
	passwordSvc svc.PasswordService,
	tokenSvc svc.TokenService,
) api.AuthUseCase {
	return &AuthUseCaseImpl{
		userRepo:    userRepo,
		tokenRepo:   tokenRepo,
		passwordSvc: passwordSvc,
		tokenSvc:    tokenSvc,
	}
}

// Register создает нового пользователя с предоставленными учетными данными.
func (a *AuthUseCaseImpl) Register(ctx context.Context, email, username, password string) (*services.TokenPair, error) {
	log := logger.Log(ctx).With(zap.String("method", methodRegister), zap.String("email", email))
	log.Debug(ctx, msgStartRegistration)

	if err := validateEmail(email); err != nil {
		log.Debug(ctx, msgInvalidEmailFormat, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errCtxValidatingEmail, err)
	}
	if username == "" {
		log.Debug(ctx, msgEmptyUsername)
		return nil, fmt.Errorf("%s: %w", errCtxValidatingUsername, entities.ErrEmptyUsername)
	}
	if err := validatePassword(password); err != nil {
		log.Debug(ctx, msgInvalidPassword, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errCtxValidatingPassword, err)
	}

	existingUser, err := a.userRepo.FindByEmail(ctx, email)
	if err != nil && !errors.Is(err, entities.ErrUserNotFound) {
		log.Error(ctx, msgErrCheckExistingUser, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errCtxCheckingUser, err)
	}
	if existingUser != nil {
		log.Debug(ctx, msgEmailExists)
		return nil, fmt.Errorf("%s: %w", errCtxEmailRegistered, services.ErrEmailAlreadyExists)
	}

	hashedPassword, err := a.passwordSvc.Hash(ctx, password)
	if err != nil {
		log.Error(ctx, msgErrHashPassword, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errCtxHashingPassword, err)
	}

	newUser := &entities.User{
		Email:        email,
		Username:     username,
		PasswordHash: hashedPassword,
	}

	createdUser, err := a.userRepo.Create(ctx, newUser)
	if err != nil {
		log.Error(ctx, msgErrCreateUser, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errCtxCreatingUser, err)
	}

	log.Info(ctx, msgUserRegistered, zap.String("userID", createdUser.ID))

	tokenPair, err := a.generateTokenPair(ctx, createdUser)
	if err != nil {
		log.Error(ctx, msgErrGenerateTokens, zap.Error(err), zap.String("userID", createdUser.ID))
		return nil, fmt.Errorf("%s: %w", errCtxGeneratingTokens, err)
	}

	log.Info(ctx, msgTokensGenerated, zap.String("userID", createdUser.ID))
	return tokenPair, nil
}

// Login аутентифицирует пользователя по email и паролю.
func (a *AuthUseCaseImpl) Login(ctx context.Context, email, password string) (*services.TokenPair, error) {
	log := logger.Log(ctx).With(zap.String("method", methodLogin), zap.String("email", email))
	log.Debug(ctx, msgLoginAttempt)

	user, err := a.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, entities.ErrUserNotFound) {
			log.Debug(ctx, msgLoginNonExistent)
			return nil, fmt.Errorf("%s: %w", errCtxInvalidCredentials, services.ErrInvalidCredentials)
		}
		log.Error(ctx, msgErrFindingUser, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errCtxFindingUser, err)
	}

	valid, err := a.passwordSvc.Verify(ctx, password, user.PasswordHash)
	if err != nil {
		log.Error(ctx, msgErrVerifyingPassword, zap.Error(err), zap.String("userID", user.ID))
		return nil, fmt.Errorf("%s: %w", errCtxVerifyingPassword, err)
	}
	if !valid {
		log.Debug(ctx, msgInvalidPasswordAuth, zap.String("userID", user.ID))
		return nil, fmt.Errorf("%s: %w", errCtxInvalidCredentials, services.ErrInvalidCredentials)
	}

	log.Info(ctx, msgUserLoggedIn, zap.String("userID", user.ID))

	tokenPair, err := a.generateTokenPair(ctx, user)
	if err != nil {
		log.Error(ctx, msgErrGenerateLoginTokens, zap.Error(err), zap.String("userID", user.ID))
		return nil, fmt.Errorf("%s: %w", errCtxGeneratingTokens, err)
	}

	log.Info(ctx, msgTokensGeneratedLogin, zap.String("userID", user.ID))
	return tokenPair, nil
}

// RefreshTokens обновляет пару токенов.
func (a *AuthUseCaseImpl) RefreshTokens(ctx context.Context, refreshToken string) (*services.TokenPair, error) {
	log := logger.Log(ctx).With(zap.String("method", methodRefreshTokens))
	log.Debug(ctx, msgRefreshingTokens)

	token, err := a.tokenRepo.FindByToken(ctx, refreshToken)
	if err != nil {
		log.Debug(ctx, msgErrInvalidRefreshToken, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errCtxFindingRefreshToken, services.ErrInvalidRefreshToken)
	}

	log = log.With(zap.String("userID", token.UserID))

	if token.IsRevoked {
		log.Debug(ctx, msgRevokedTokenAttempt)
		return nil, fmt.Errorf("%s: %w", errCtxTokenRevoked, services.ErrRevokedRefreshToken)
	}

	user, err := a.userRepo.FindByID(ctx, token.UserID)
	if err != nil {
		log.Error(ctx, msgErrFindingUserForToken, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errCtxFindingUser, err)
	}

	if err := a.tokenRepo.RevokeToken(ctx, refreshToken); err != nil {
		log.Error(ctx, msgErrRevokingOldToken, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errCtxRevokingOldToken, err)
	}

	log.Debug(ctx, msgOldTokenRevoked)

	tokenPair, err := a.generateTokenPair(ctx, user)
	if err != nil {
		log.Error(ctx, msgErrGenerateRefreshTokens, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errCtxGeneratingNewTokens, err)
	}

	log.Info(ctx, msgTokensRefreshed)
	return tokenPair, nil
}

// Logout отзывает токен.
func (a *AuthUseCaseImpl) Logout(ctx context.Context, refreshToken string) error {
	log := logger.Log(ctx).With(zap.String("method", methodLogout))
	log.Debug(ctx, msgProcessingLogout)

	token, err := a.tokenRepo.FindByToken(ctx, refreshToken)
	if err == nil && token != nil {
		log = log.With(zap.String("userID", token.UserID))
	}

	err = a.tokenRepo.RevokeToken(ctx, refreshToken)
	if err != nil {
		log.Error(ctx, msgErrRevokingRefreshToken, zap.Error(err))
		return fmt.Errorf("%s: %w", errCtxRevokingToken, err)
	}

	log.Info(ctx, msgUserLoggedOut)
	return nil
}

// Вспомогательная функция для генерации пары токенов.
func (a *AuthUseCaseImpl) generateTokenPair(ctx context.Context, user *entities.User) (*services.TokenPair, error) {
	log := logger.Log(ctx).With(
		zap.String("method", methodGenerateTokens),
		zap.String("userID", user.ID),
	)

	accessToken, accessExpires, err := a.tokenSvc.GenerateAccessToken(ctx, user.ID, user.Username)
	if err != nil {
		log.Error(ctx, msgErrGenerateAccessToken, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errCtxGeneratingAccessToken, services.ErrTokenGenerationFailed)
	}

	refreshToken, refreshExpires, err := a.tokenSvc.GenerateRefreshToken(ctx, user.ID)
	if err != nil {
		log.Error(ctx, msgErrGenerateRefreshToken, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errCtxGeneratingRefreshToken, services.ErrTokenGenerationFailed)
	}

	if err := a.tokenRepo.StoreRefreshToken(ctx, &services.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: refreshExpires,
		IsRevoked: false,
	}); err != nil {
		log.Error(ctx, msgErrStoreRefreshToken, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errCtxStoringRefreshToken, err)
	}

	log.Debug(ctx, msgTokenPairGenerated)

	return &services.TokenPair{
		UserID:       user.ID,
		Username:     user.Username,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    accessExpires,
	}, nil
}

// Валидация email.
func validateEmail(email string) error {
	if email == "" {
		return entities.ErrInvalidEmail
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return entities.ErrInvalidEmail
	}

	return nil
}

// Валидация пароля.
func validatePassword(password string) error {
	if len(password) < 8 {
		return entities.ErrPasswordTooShort
	}

	hasLetter := regexp.MustCompile(`[a-zA-Z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`\d`).MatchString(password)

	if !hasLetter || !hasDigit {
		return entities.ErrPasswordTooWeak
	}

	return nil
}

// GetValidatePasswordFunc экспортирует функцию validatePassword для тестирования.
func GetValidatePasswordFunc() func(string) error {
	return validatePassword
}

// GetValidateEmailFunc экспортирует функцию validateEmail для тестирования.
func GetValidateEmailFunc() func(string) error {
	return validateEmail
}

// GetGenerateTokenPairFunc возвращает функцию создания пары токенов для тестирования.
func (a *AuthUseCaseImpl) GetGenerateTokenPairFunc() func(context.Context, *entities.User) (*services.TokenPair, error) {
	return a.generateTokenPair
}
