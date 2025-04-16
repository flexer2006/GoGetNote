package main

import (
	"fmt"
	"os"

	"gitlab.crja72.ru/golang/2025/spring/course/projects/go9/gogetnote/internal/notes"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	dsn := "host=localhost user=noteuser password=securepassword dbname=note port=5432 sslmode=disable"

	// Подключение к базе данных SQLite (или PostgreSQL, если используется)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		fmt.Println("failed to connect database:", err)
		os.Exit(1)
	}

	db.AutoMigrate(&notes.Note{}) // Это создаст таблицу "notes" в базе данных
}
