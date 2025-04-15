// Package config предоставляет функциональность для загрузки конфигурации из переменных окружения.
package config

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/ilyakaznacheev/cleanenv"
	"go.uber.org/zap"

	"gitlab.crja72.ru/golang/2025/spring/course/projects/go9/gogetnote/pkg/logger"
)

const (
	msgLoadingConfiguration    = "loading configuration"
	msgConfigurationLoaded     = "configuration loaded successfully"
	msgFailedLoadConfiguration = "failed to load configuration"

	errFailedCreateLogger      = "failed to create logger"
	errFailedLoadConfiguration = "failed to load configuration"

	attrService = "service"
	attrPath    = "path"
)

func Load[T any](ctx context.Context, serviceName string) (*T, error) {
	log, err := logger.FromContext(ctx)
	if err != nil {
		log, err = logger.NewLogger()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", errFailedCreateLogger, err)
		}
		ctx = logger.NewContext(ctx, log)
	}

	envPath := filepath.Join("deploy", ".env")

	log.Info(ctx, msgLoadingConfiguration,
		zap.String(attrService, serviceName),
		zap.String(attrPath, envPath))

	var cfg T

	err = cleanenv.ReadConfig(envPath, &cfg)
	if err != nil {
		log.Error(ctx, msgFailedLoadConfiguration,
			zap.String(attrService, serviceName),
			zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errFailedLoadConfiguration, err)
	}

	log.Info(ctx, msgConfigurationLoaded,
		zap.String(attrService, serviceName))

	return &cfg, nil
}
