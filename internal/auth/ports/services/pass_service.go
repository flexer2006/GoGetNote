package services

import "context"

// PasswordService определяет операции для манипулирования паролем.
type PasswordService interface {
	Hash(ctx context.Context, password string) (string, error)

	Verify(ctx context.Context, password, hash string) (bool, error)
}
