package authusecase_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gogetnote/internal/auth/app"
	"gogetnote/internal/auth/domain/entities"
)

func TestValidateEmail(t *testing.T) {
	validateEmail := app.GetValidateEmailFunc()

	tests := []struct {
		name    string
		email   string
		wantErr error
	}{
		{
			name:    "valid standard email",
			email:   "test@example.com",
			wantErr: nil,
		},
		{
			name:    "valid email with numbers",
			email:   "user123@example.com",
			wantErr: nil,
		},
		{
			name:    "valid email with dot in local part",
			email:   "first.last@example.com",
			wantErr: nil,
		},
		{
			name:    "valid email with plus",
			email:   "user+tag@example.com",
			wantErr: nil,
		},
		{
			name:    "valid email with subdomain",
			email:   "user@sub.example.com",
			wantErr: nil,
		},
		{
			name:    "empty email",
			email:   "",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "email without @",
			email:   "userexample.com",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "email without domain",
			email:   "user@",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "email without local part",
			email:   "@example.com",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "email with invalid characters",
			email:   "user*name@example.com",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "email with too short domain",
			email:   "user@e.c",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "email with spaces",
			email:   "user name@example.com",
			wantErr: entities.ErrInvalidEmail,
		},
	}

	for _, ttt := range tests {
		t.Run(ttt.name, func(t *testing.T) {
			err := validateEmail(ttt.email)

			if ttt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, ttt.wantErr)
			}
		})
	}
}
