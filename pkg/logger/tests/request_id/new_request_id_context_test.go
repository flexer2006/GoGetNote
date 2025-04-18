package request_id_test

import (
	"context"
	"testing"

	"gogetnote/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	msgShouldRetrieveRequestID           = "should be able to retrieve request ID"
	msgRetrievedIDShouldMatchStored      = "retrieved ID should match what was stored"
	msgGeneratedIDShouldNotBeEmpty       = "generated ID should not be empty"
	msgGeneratedRequestIDsShouldBeUnique = "generated request IDs should be unique"
	msgShouldRetrieveIDFromChildContext  = "should be able to retrieve request ID from child context"
	msgRetrievedIDShouldMatchParent      = "retrieved ID should match what was stored in parent"
	msgRetrievedIDShouldBeFromRecent     = "retrieved ID should be from the most recent call"
)

type testChildKeyType struct{}

var childTestKey = testChildKeyType{}

func TestNewRequestIDContext(t *testing.T) {
	t.Run("stores provided request ID in context", func(t *testing.T) {
		baseCtx := context.Background()

		customID := "test-request-id-123"

		ctx := logger.NewRequestIDContext(baseCtx, customID)

		assert.NotSame(t, baseCtx, ctx)

		retrievedID, ok := logger.GetRequestID(ctx)
		assert.True(t, ok, msgShouldRetrieveRequestID)
		assert.Equal(t, customID, retrievedID, msgRetrievedIDShouldMatchStored)
	})

	t.Run("generates new request ID when empty string provided", func(t *testing.T) {
		baseCtx := context.Background()

		ctx := logger.NewRequestIDContext(baseCtx, "")

		retrievedID, ok := logger.GetRequestID(ctx)
		assert.True(t, ok, msgShouldRetrieveRequestID)
		assert.NotEmpty(t, retrievedID, msgGeneratedIDShouldNotBeEmpty)
	})

	t.Run("generates unique IDs for multiple calls", func(t *testing.T) {
		ctx1 := logger.NewRequestIDContext(context.Background(), "")
		ctx2 := logger.NewRequestIDContext(context.Background(), "")

		id1, ok1 := logger.GetRequestID(ctx1)
		require.True(t, ok1)

		id2, ok2 := logger.GetRequestID(ctx2)
		require.True(t, ok2)

		assert.NotEqual(t, id1, id2, msgGeneratedRequestIDsShouldBeUnique)
	})

	t.Run("works with derived contexts", func(t *testing.T) {
		customID := "parent-request-id"
		parentCtx := logger.NewRequestIDContext(context.Background(), customID)

		childValue := "child-value"
		childCtx := context.WithValue(parentCtx, childTestKey, childValue)

		retrievedID, ok := logger.GetRequestID(childCtx)
		assert.True(t, ok, msgShouldRetrieveIDFromChildContext)
		assert.Equal(t, customID, retrievedID, msgRetrievedIDShouldMatchParent)

		assert.Equal(t, childValue, childCtx.Value(childTestKey))
	})

	t.Run("supports multiple request ID contexts in a chain", func(t *testing.T) {
		firstID := "first-request-id"
		firstCtx := logger.NewRequestIDContext(context.Background(), firstID)

		secondID := "second-request-id"
		secondCtx := logger.NewRequestIDContext(firstCtx, secondID)

		retrievedID, ok := logger.GetRequestID(secondCtx)
		assert.True(t, ok, msgShouldRetrieveRequestID)
		assert.Equal(t, secondID, retrievedID, msgRetrievedIDShouldBeFromRecent)
	})
}
