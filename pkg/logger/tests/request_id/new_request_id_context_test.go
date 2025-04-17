package request_id_test

import (
	"context"
	"testing"

	"gogetnote/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRequestIDContext(t *testing.T) {
	t.Run("stores provided request ID in context", func(t *testing.T) {
		baseCtx := context.Background()

		customID := "test-request-id-123"

		ctx := logger.NewRequestIDContext(baseCtx, customID)

		assert.NotSame(t, baseCtx, ctx)

		retrievedID, ok := logger.GetRequestID(ctx)
		assert.True(t, ok, "Should be able to retrieve request ID")
		assert.Equal(t, customID, retrievedID, "Retrieved ID should match what was stored")
	})

	t.Run("generates new request ID when empty string provided", func(t *testing.T) {
		baseCtx := context.Background()

		ctx := logger.NewRequestIDContext(baseCtx, "")

		retrievedID, ok := logger.GetRequestID(ctx)
		assert.True(t, ok, "Should be able to retrieve request ID")
		assert.NotEmpty(t, retrievedID, "Generated ID should not be empty")
	})

	t.Run("generates unique IDs for multiple calls", func(t *testing.T) {
		ctx1 := logger.NewRequestIDContext(context.Background(), "")
		ctx2 := logger.NewRequestIDContext(context.Background(), "")

		id1, ok1 := logger.GetRequestID(ctx1)
		require.True(t, ok1)

		id2, ok2 := logger.GetRequestID(ctx2)
		require.True(t, ok2)

		assert.NotEqual(t, id1, id2, "Generated request IDs should be unique")
	})

	t.Run("works with derived contexts", func(t *testing.T) {
		customID := "parent-request-id"
		parentCtx := logger.NewRequestIDContext(context.Background(), customID)

		childKey := "child-key"
		childValue := "child-value"
		childCtx := context.WithValue(parentCtx, childKey, childValue)

		retrievedID, ok := logger.GetRequestID(childCtx)
		assert.True(t, ok, "Should be able to retrieve request ID from child context")
		assert.Equal(t, customID, retrievedID, "Retrieved ID should match what was stored in parent")

		assert.Equal(t, childValue, childCtx.Value(childKey))
	})

	t.Run("supports multiple request ID contexts in a chain", func(t *testing.T) {
		firstID := "first-request-id"
		firstCtx := logger.NewRequestIDContext(context.Background(), firstID)

		secondID := "second-request-id"
		secondCtx := logger.NewRequestIDContext(firstCtx, secondID)

		retrievedID, ok := logger.GetRequestID(secondCtx)
		assert.True(t, ok, "Should be able to retrieve request ID")
		assert.Equal(t, secondID, retrievedID, "Retrieved ID should be from the most recent call")
	})
}
