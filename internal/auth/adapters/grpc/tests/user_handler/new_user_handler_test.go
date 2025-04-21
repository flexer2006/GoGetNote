package userhandlergo_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/emptypb"

	grpcAdapter "gogetnote/internal/auth/adapters/grpc"
	authv1 "gogetnote/pkg/api/auth/v1"
)

const (
	handlerNotNilAssertion          = "handler should not be nil"
	handlerShouldImplementAssertion = "handler should implement UserServiceServer interface"
	getUserProfileAssertion         = "GetUserProfile should return error when userID is missing"
)

func TestNewUserHandler(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
	}{
		{
			name: "successfully create user handler",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockUseCase := new(UserUseCase)
			mockTokenSvc := new(TokenService)

			handler := grpcAdapter.NewUserHandler(mockUseCase, mockTokenSvc)

			assert.NotNil(t, handler, handlerNotNilAssertion)

			_, ok := interface{}(handler).(authv1.UserServiceServer)
			assert.True(t, ok, handlerShouldImplementAssertion)

			empty := &emptypb.Empty{}
			ctx := context.Background()

			_, err := handler.GetUserProfile(ctx, empty)
			assert.Error(t, err, getUserProfileAssertion)
		})
	}
}
