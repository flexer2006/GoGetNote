// Package notes using for redis client
package notes

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

// NewRedisClient создает новый клиент Redis с заданными параметрами.
func NewRedisClient() *redis.Client {
	// Создаем клиент Redis
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	client := redis.NewClient(&redis.Options{
		Addr: redisAddr, // Адрес Redis
		// Password:     os.Getenv("REDIS_PASSWORD"), // Пароль (если нужно)
		Password:     "",              // Пароля нет
		DB:           0,               // База данных Redis
		DialTimeout:  5 * time.Second, // Таймаут на подключение
		ReadTimeout:  3 * time.Second, // Таймаут на чтение
		WriteTimeout: 3 * time.Second, // Таймаут на запись
	})

	// Проверка соединения с Redis с помощью PING
	ctx := context.Background()
	pong, err := client.Ping(ctx).Result()
	if err != nil {
		fmt.Println("Ошибка при подключении к Redis:", err)
		return nil
	}

	// Если команда PING вернула "PONG", значит соединение успешно
	if pong == "PONG" {
		fmt.Println("Подключение к Redis успешно!")
	} else {
		fmt.Println("Не удалось подключиться к Redis.")
		os.Exit(1)
	}
	return client
}
