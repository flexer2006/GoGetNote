package main

import (
	"log"
	"net"

	"gitlab.crja72.ru/golang/2025/spring/course/projects/go9/gogetnote/internal/notes"
	notesv1 "gitlab.crja72.ru/golang/2025/spring/course/projects/go9/gogetnote/pkg/api/notes/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	// Подключение к базе данных
	dsn := "host=localhost user=noteuser password=securepassword dbname=note port=5432 sslmode=disable"
	db := notes.InitDB(dsn)

	// Создание репозитория для заметок
	noteRepository := notes.NewNoteRepository(db.DB)

	// Создание сервиса заметок
	noteService := notes.NewNoteService(noteRepository)

	// Создание GRPC сервера
	grpcServer := grpc.NewServer()
	notesv1.RegisterNoteServiceServer(grpcServer, notes.NewNoteGRPCServer(noteService))
	reflection.Register(grpcServer)

	// Прослушивание порта
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// Запуск gRPC сервера
	log.Println("Server started on :50051")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
