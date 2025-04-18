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
			name:    "Valid standard email",
			email:   "test@example.com",
			wantErr: nil,
		},
		{
			name:    "Valid email with numbers",
			email:   "user123@example.com",
			wantErr: nil,
		},
		{
			name:    "Valid email with dot in local part",
			email:   "first.last@example.com",
			wantErr: nil,
		},
		{
			name:    "Valid email with plus",
			email:   "user+tag@example.com",
			wantErr: nil,
		},
		{
			name:    "Valid email with subdomain",
			email:   "user@sub.example.com",
			wantErr: nil,
		},
		{
			name:    "Empty email",
			email:   "",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "Email without @",
			email:   "userexample.com",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "Email without domain",
			email:   "user@",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "Email without local part",
			email:   "@example.com",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "Email with invalid characters",
			email:   "user*name@example.com",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "Email with too short domain",
			email:   "user@e.c",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "Email with spaces",
			email:   "user name@example.com",
			wantErr: entities.ErrInvalidEmail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEmail(tt.email)

			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}
