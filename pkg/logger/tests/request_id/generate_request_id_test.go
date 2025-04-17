package request_id_test

import (
	"testing"

	"gogetnote/pkg/logger"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRequestID(t *testing.T) {
	t.Run("generates non-empty string", func(t *testing.T) {
		id := logger.GenerateRequestID()

		assert.NotEmpty(t, id, "Generated request ID should not be empty")
	})

	t.Run("generates unique IDs", func(t *testing.T) {
		id1 := logger.GenerateRequestID()
		id2 := logger.GenerateRequestID()
		id3 := logger.GenerateRequestID()

		assert.NotEqual(t, id1, id2, "Generated IDs should be unique")
		assert.NotEqual(t, id1, id3, "Generated IDs should be unique")
		assert.NotEqual(t, id2, id3, "Generated IDs should be unique")
	})

	t.Run("generates valid UUIDs", func(t *testing.T) {
		id := logger.GenerateRequestID()

		parsedUUID, err := uuid.Parse(id)
		require.NoError(t, err, "Generated ID should be a valid UUID")
		assert.NotEmpty(t, parsedUUID, "Parsed UUID should not be empty")
	})

	t.Run("generates UUID v4", func(t *testing.T) {
		id := logger.GenerateRequestID()

		parsedUUID, err := uuid.Parse(id)
		require.NoError(t, err)

		assert.Equal(t, uuid.Version(4), parsedUUID.Version(), "Should generate UUID version 4")

		assert.Equal(t, uuid.RFC4122, parsedUUID.Variant(), "Should generate UUID with RFC4122 variant")
	})
}
