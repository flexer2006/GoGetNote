package cache_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/gateway/adapters/cache"
	"gogetnote/internal/gateway/config"
	cachePorts "gogetnote/internal/gateway/ports/cache"
)

func mockRedisServer(t *testing.T) (*miniredis.Miniredis, string) {
	t.Helper()

	s, err := miniredis.Run()
	require.NoError(t, err)

	t.Cleanup(func() {
		s.Close()
	})

	return s, s.Addr()
}

func TestNewRedisCache_Success(t *testing.T) {
	_, addr := mockRedisServer(t)
	ctx := context.Background()

	cfg := &config.RedisConfig{
		Host:            "localhost",
		Port:            6379,
		Password:        "",
		DB:              0,
		ConnectTimeout:  5 * time.Second,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
		PoolSize:        10,
		MinIdle:         5,
		IdleTimeout:     5 * time.Minute,
		MaxConnLifetime: 1 * time.Hour,
		DefaultTTL:      24 * time.Hour,
	}

	host, portStr, _ := strings.Cut(addr, ":")
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	cfg.Host = host
	cfg.Port = port

	redisCache, err := cache.NewRedisCache(ctx, cfg)

	require.NoError(t, err)
	require.NotNil(t, redisCache)

	_, ok := redisCache.(cachePorts.Cache)
	assert.True(t, ok, "should implement Cache interface")

	// Verify we can close the connection
	assert.NoError(t, redisCache.Close(), "should close without errors")
}

func TestNewRedisCache_ConnectionFailure(t *testing.T) {
	ctx := context.Background()

	cfg := &config.RedisConfig{
		Host:           "nonexistent.host",
		Port:           12345,
		ConnectTimeout: 100 * time.Millisecond,
		ReadTimeout:    100 * time.Millisecond,
		WriteTimeout:   100 * time.Millisecond,
	}

	// Act
	redisCache, err := cache.NewRedisCache(ctx, cfg)

	// Assert
	assert.Error(t, err, "Expected error when Redis connection fails")
	assert.Nil(t, redisCache, "Cache should be nil when connection fails")
	assert.Contains(t, err.Error(), "failed to connect to redis")
}

func TestNewRedisCache_PingFailure(t *testing.T) {
	ctx := context.Background()
	cfg := &config.RedisConfig{
		Host:           "localhost",
		Port:           6379,
		ConnectTimeout: 1 * time.Second,
		DefaultTTL:     24 * time.Hour,
	}

	ctxWithCancel, cancel := context.WithCancel(ctx)
	cancel()

	redisCache, err := cache.NewRedisCache(ctxWithCancel, cfg)

	assert.Error(t, err, "Expected error when Redis ping fails")
	assert.Nil(t, redisCache, "Cache should be nil when ping fails")
}

func TestNewRedisCache_ValidatesAndUsesConfig(t *testing.T) {
	s, addr := mockRedisServer(t)
	ctx := context.Background()

	testTTL := 10 * time.Minute
	testDB := 1

	host, portStr, _ := strings.Cut(addr, ":")
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	cfg := &config.RedisConfig{
		Host:            host,
		Port:            port,
		DB:              testDB,
		DefaultTTL:      testTTL,
		ConnectTimeout:  2 * time.Second,
		ReadTimeout:     1 * time.Second,
		WriteTimeout:    1 * time.Second,
		PoolSize:        5,
		MinIdle:         2,
		IdleTimeout:     30 * time.Second,
		MaxConnLifetime: 5 * time.Minute,
	}

	s.Select(testDB)

	redisCache, err := cache.NewRedisCache(ctx, cfg)
	require.NoError(t, err)

	testKey := "test_key"
	testValue := "test_value"
	err = redisCache.Set(ctx, testKey, testValue, 0)
	require.NoError(t, err)

	ttl := s.TTL(testKey)
	assert.Greater(t, ttl.Seconds(), 0.0, "Key should have TTL set")
	assert.Less(t, ttl.Seconds(), testTTL.Seconds()+5.0, "TTL should be close to the configured value")
	assert.Greater(t, ttl.Seconds(), testTTL.Seconds()-5.0, "TTL should be close to the configured value")

	assert.NoError(t, redisCache.Close())
}
