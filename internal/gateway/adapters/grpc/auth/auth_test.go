package auth_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/undefinedlabs/go-mpatch"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	"gogetnote/internal/gateway/adapters/grpc/auth"
	"gogetnote/internal/gateway/config"
	authv1 "gogetnote/pkg/api/auth/v1"
)

const bufSize = 1024 * 1024

func mockGRPCClientConfig(address string) *config.GRPCClientConfig {
	return &config.GRPCClientConfig{
		AuthService: config.GRPCServiceConfig{
			Host: address,
			Port: 0,
		},
	}
}

type mockAuthServer struct {
	authv1.UnimplementedAuthServiceServer
}

type mockUserServer struct {
	authv1.UnimplementedUserServiceServer
}

func safeUnpatch(t *testing.T, patch *mpatch.Patch) {
	t.Helper()
	if patch != nil {
		err := patch.Unpatch()
		if err != nil {
			t.Logf("Failed to unpatch: %v", err)
		}
	}
}

func TestNewAuthClient_ConnectionFailure(t *testing.T) {
	ctx := context.Background()
	cfg := mockGRPCClientConfig("invalid-address:12345")

	newClientPatch, err := mpatch.PatchMethod(grpc.NewClient, func(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
		return nil, errors.New("connection refused")
	})
	require.NoError(t, err, "Failed to patch grpc.NewClient")
	defer safeUnpatch(t, newClientPatch)

	client, err := auth.NewAuthClient(ctx, cfg)

	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "failed to connect to auth service")
}

func TestNewAuthClient_ConnectionTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	cfg := mockGRPCClientConfig("localhost:50051")

	conn, err := grpc.DialContext(
		ctx,
		"localhost:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	newClientPatch, err := mpatch.PatchMethod(grpc.NewClient, func(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
		return conn, nil
	})
	require.NoError(t, err, "Failed to patch grpc.NewClient")
	defer safeUnpatch(t, newClientPatch)

	getStatePatchType := reflect.TypeOf(&grpc.ClientConn{})
	getStatePatch, err := mpatch.PatchInstanceMethodByName(getStatePatchType, "GetState", func(_ *grpc.ClientConn) connectivity.State {
		return connectivity.Connecting
	})
	require.NoError(t, err, "Failed to patch GetState")
	defer safeUnpatch(t, getStatePatch)

	waitPatchType := reflect.TypeOf(&grpc.ClientConn{})
	waitPatch, err := mpatch.PatchInstanceMethodByName(waitPatchType, "WaitForStateChange", func(_ *grpc.ClientConn, _ context.Context, _ connectivity.State) bool {
		return false
	})
	require.NoError(t, err, "Failed to patch WaitForStateChange")
	defer safeUnpatch(t, waitPatch)

	client, err := auth.NewAuthClient(ctx, cfg)

	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Equal(t, auth.ErrAuthServiceConnectionTimeout, err)
}

func TestNewAuthClient_CloseError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	cfg := mockGRPCClientConfig("localhost:50051")
	closeErr := errors.New("failed to close connection")

	conn, err := grpc.DialContext(
		ctx,
		"localhost:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	newClientPatch, err := mpatch.PatchMethod(grpc.NewClient, func(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
		return conn, nil
	})
	require.NoError(t, err, "Failed to patch grpc.NewClient")
	defer safeUnpatch(t, newClientPatch)

	getStatePatchType := reflect.TypeOf(&grpc.ClientConn{})
	getStatePatch, err := mpatch.PatchInstanceMethodByName(getStatePatchType, "GetState", func(_ *grpc.ClientConn) connectivity.State {
		return connectivity.Connecting
	})
	require.NoError(t, err, "Failed to patch GetState")
	defer safeUnpatch(t, getStatePatch)

	waitPatchType := reflect.TypeOf(&grpc.ClientConn{})
	waitPatch, err := mpatch.PatchInstanceMethodByName(waitPatchType, "WaitForStateChange", func(_ *grpc.ClientConn, _ context.Context, _ connectivity.State) bool {
		return false
	})
	require.NoError(t, err, "Failed to patch WaitForStateChange")
	defer safeUnpatch(t, waitPatch)

	closePatchType := reflect.TypeOf(&grpc.ClientConn{})
	closePatch, err := mpatch.PatchInstanceMethodByName(closePatchType, "Close", func(_ *grpc.ClientConn) error {
		return closeErr
	})
	require.NoError(t, err, "Failed to patch Close")
	defer safeUnpatch(t, closePatch)

	client, err := auth.NewAuthClient(ctx, cfg)

	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "failed to close connection")
}

func TestClose_Success(t *testing.T) {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	require.NoError(t, err)

	client := &auth.Client{}

	clientValue := reflect.ValueOf(client).Elem()
	connField := clientValue.FieldByName("conn")
	if !connField.IsValid() {
		t.Fatal("conn field not found in Client struct")
	}
	connField = reflect.NewAt(connField.Type(), connField.Addr().UnsafePointer()).Elem()
	connField.Set(reflect.ValueOf(conn))

	err = client.Close()
	assert.NoError(t, err)
}

func TestClose_Error(t *testing.T) {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	require.NoError(t, err)

	client := &auth.Client{}

	clientValue := reflect.ValueOf(client).Elem()
	connField := clientValue.FieldByName("conn")
	if !connField.IsValid() {
		t.Fatal("conn field not found in Client struct")
	}
	connField = reflect.NewAt(connField.Type(), connField.Addr().UnsafePointer()).Elem()
	connField.Set(reflect.ValueOf(conn))

	expectedError := errors.New("connection close error")
	closePatchType := reflect.TypeOf(&grpc.ClientConn{})
	closePatch, err := mpatch.PatchInstanceMethodByName(closePatchType, "Close", func(_ *grpc.ClientConn) error {
		return expectedError
	})
	require.NoError(t, err, "Failed to patch Close")
	defer safeUnpatch(t, closePatch)

	err = client.Close()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to close grpc connection")
	assert.ErrorIs(t, err, expectedError)
}

func TestClose_NilConnection(t *testing.T) {

	client := &auth.Client{}

	err := client.Close()
	assert.NoError(t, err, "Close should not return error when connection is nil")
}

func TestCreateClientWithConnection(t *testing.T) {

	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	require.NoError(t, err)

	authClient := authv1.NewAuthServiceClient(conn)
	userClient := authv1.NewUserServiceClient(conn)

	client := &auth.Client{}

	clientValue := reflect.ValueOf(client).Elem()

	authClientField := clientValue.FieldByName("authClient")
	if !authClientField.IsValid() {
		t.Fatal("authClient field not found in Client struct")
	}
	authClientField = reflect.NewAt(authClientField.Type(), authClientField.Addr().UnsafePointer()).Elem()
	authClientField.Set(reflect.ValueOf(authClient))

	userClientField := clientValue.FieldByName("userClient")
	if !userClientField.IsValid() {
		t.Fatal("userClient field not found in Client struct")
	}
	userClientField = reflect.NewAt(userClientField.Type(), userClientField.Addr().UnsafePointer()).Elem()
	userClientField.Set(reflect.ValueOf(userClient))

	connField := clientValue.FieldByName("conn")
	if !connField.IsValid() {
		t.Fatal("conn field not found in Client struct")
	}
	connField = reflect.NewAt(connField.Type(), connField.Addr().UnsafePointer()).Elem()
	connField.Set(reflect.ValueOf(conn))

	err = client.Close()
	assert.NoError(t, err)
}
