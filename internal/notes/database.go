// Package notes using for database
package notes

import (
	"fmt"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// DB структура для использования с GORM.
type DB struct {
	*gorm.DB
}

// InitDB Функция инициализации базы данных.
func InitDB(connStr string) *DB {
	// Открытие соединения с базой данных
	gormDB, err := gorm.Open(postgres.Open(connStr), &gorm.Config{})
	if err != nil {
		fmt.Println("failed to connect database:", err)
		os.Exit(1)
	}
	// Возвращаем DB с подключением
	return &DB{
		DB: gormDB,
	}
}
