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
			name:     "valid password with letters and digits",
			password: "password123",
			wantErr:  nil,
		},
		{
			name:     "valid complex password",
			password: "P@ssw0rd!123",
			wantErr:  nil,
		},
		{
			name:     "password too short",
			password: "pass12",
			wantErr:  entities.ErrPasswordTooShort,
		},
		{
			name:     "password without letters",
			password: "12345678",
			wantErr:  entities.ErrPasswordTooWeak,
		},
		{
			name:     "password without digits",
			password: "passwordonly",
			wantErr:  entities.ErrPasswordTooWeak,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  entities.ErrPasswordTooShort,
		},
	}

	for _, ttt := range tests {
		t.Run(ttt.name, func(t *testing.T) {
			err := validatePassword(ttt.password)

			if ttt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, ttt.wantErr)
			}
		})
	}
}
