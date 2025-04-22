package services

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"gogetnote/internal/gateway/app/dto"
	"gogetnote/pkg/logger"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

// GetUserProfile получает профиль пользователя.
func (s *AuthServiceImpl) GetUserProfile(ctx context.Context) (*dto.UserProfileResponse, error) {
	log := logger.Log(ctx)
	log.Info(ctx, LogServiceGetProfile)

	// Получаем токен из контекста для использования как ключ кэша.
	md, ok := metadata.FromIncomingContext(ctx)
	token := ""
	if ok && len(md["authorization"]) > 0 {
		token = md["authorization"][0]
		tokenHash := hashToken(token)
		cacheKey := ProfileCacheKeyPrefix + tokenHash

		cachedProfile, err := s.cache.Get(ctx, cacheKey)
		if err == nil && cachedProfile != "" {
			var profile dto.UserProfileResponse
			if err := json.Unmarshal([]byte(cachedProfile), &profile); err == nil {
				log.Debug(ctx, "User profile found in cache")
				return &profile, nil
			}
		}
	}

	// Если в кэше нет или произошла ошибка, запрашиваем из сервиса с отказоустойчивостью.
	result, err := s.resilience.ExecuteWithResultTokenResponse(ctx, "GetUserProfile", func() (any, error) {
		profile, err := s.authClient.GetUserProfile(ctx)
		if err != nil {
			log.Error(ctx, ErrorGetProfileFailed, zap.Error(err))
			return nil, fmt.Errorf("%s: %w", ErrorGetProfileFailed, err)
		}

		profileDto := &dto.UserProfileResponse{
			UserID:    profile.UserId,
			Email:     profile.Email,
			Username:  profile.Username,
			CreatedAt: profile.CreatedAt.AsTime(),
		}

		if token != "" {
			tokenHash := hashToken(token)
			cacheKey := ProfileCacheKeyPrefix + tokenHash

			profileJSON, err := json.Marshal(profileDto)
			if err == nil {
				// Fix: Use parent ctx instead of context.Background()
				cacheCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()

				err := s.cache.Set(cacheCtx, cacheKey, string(profileJSON), 15*time.Minute)
				if err != nil {
					log.Warn(ctx, "Failed to cache user profile", zap.Error(err))
				} else {
					log.Debug(ctx, "User profile cached successfully")
				}
			}
		}

		return profileDto, nil
	})

	if err != nil {
		return nil, fmt.Errorf("profile retrieval failed: %w", err)
	}

	return result.(*dto.UserProfileResponse), nil
}

// hashToken создает хеш токена для использования в качестве ключа кэша.
func hashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return fmt.Sprintf("%x", h.Sum(nil))
}
