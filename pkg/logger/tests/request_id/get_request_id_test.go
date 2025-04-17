package request_id_test

import (
	"context"
	"testing"

	"gogetnote/pkg/logger"

	"github.com/stretchr/testify/assert"
)

func TestGetRequestID(t *testing.T) {
	t.Run("returns request ID when present in context", func(t *testing.T) {
		expectedID := "test-request-id-123"
		ctx := logger.NewRequestIDContext(context.Background(), expectedID)

		retrievedID, ok := logger.GetRequestID(ctx)

		assert.True(t, ok, "Should indicate request ID was found")
		assert.Equal(t, expectedID, retrievedID, "Should return the correct request ID")
	})

	t.Run("returns false when no request ID in context", func(t *testing.T) {
		ctx := context.Background()

		retrievedID, ok := logger.GetRequestID(ctx)

		assert.False(t, ok, "Should indicate no request ID was found")
		assert.Empty(t, retrievedID, "Should return empty string when not found")
	})

	t.Run("handles auto-generated request IDs", func(t *testing.T) {
		ctx := logger.NewRequestIDContext(context.Background(), "")

		retrievedID, ok := logger.GetRequestID(ctx)

		assert.True(t, ok, "Should indicate request ID was found")
		assert.NotEmpty(t, retrievedID, "Should return non-empty auto-generated ID")
	})

	t.Run("returns same ID for derived contexts", func(t *testing.T) {
		expectedID := "parent-request-id"
		parentCtx := logger.NewRequestIDContext(context.Background(), expectedID)

		childCtx := context.WithValue(parentCtx, "some-key", "some-value")

		retrievedID, ok := logger.GetRequestID(childCtx)

		assert.True(t, ok, "Should find ID in derived context")
		assert.Equal(t, expectedID, retrievedID, "Should return the ID from parent context")
	})
}
