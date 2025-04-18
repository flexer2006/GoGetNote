package authusecase_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gogetnote/internal/auth/app"
	"gogetnote/internal/auth/domain/entities"
)

func TestValidatePassword(t *testing.T) {
	validatePassword := app.GetValidatePasswordFunc()

	tests := []struct {
		name     string
		password string
		wantErr  error
	}{
		{
			name:     "Valid password with letters and digits",
			password: "password123",
			wantErr:  nil,
		},
		{
			name:     "Valid complex password",
			password: "P@ssw0rd!123",
			wantErr:  nil,
		},
		{
			name:     "Password too short",
			password: "pass12",
			wantErr:  entities.ErrPasswordTooShort,
		},
		{
			name:     "Password without letters",
			password: "12345678",
			wantErr:  entities.ErrPasswordTooWeak,
		},
		{
			name:     "Password without digits",
			password: "passwordonly",
			wantErr:  entities.ErrPasswordTooWeak,
		},
		{
			name:     "Empty password",
			password: "",
			wantErr:  entities.ErrPasswordTooShort,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePassword(tt.password)

			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}
