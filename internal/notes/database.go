package notes

import (
	"fmt"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Структура DB для использования с GORM
type DB struct {
	*gorm.DB
}

// Функция инициализации базы данных
func InitDB(conf string) *DB {
	// Открытие соединения с базой данных
	db, err := gorm.Open(postgres.Open(conf), &gorm.Config{})
	if err != nil {
		fmt.Println("failed to connect database:", err)
		os.Exit(1)
	}
	// Возвращаем DB с подключением
	return &DB{
		DB: db,
	}
}