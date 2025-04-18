package request_id_test

import (
	"testing"

	"gogetnote/pkg/logger"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	msgIDShouldNotBeEmpty  = "generated request ID should not be empty"
	msgIDsShouldBeUnique   = "generated IDs should be unique"
	msgIDShouldBeValidUUID = "generated ID should be a valid UUID"
	msgParsedUUIDNotEmpty  = "parsed UUID should not be empty"
	msgShouldBeUUIDv4      = "should generate UUID version 4"
	msgShouldBeRFC4122     = "should generate UUID with RFC4122 variant"
)

func TestGenerateRequestID(t *testing.T) {
	t.Run("generates non-empty string", func(t *testing.T) {
		id := logger.GenerateRequestID()

		assert.NotEmpty(t, id, msgIDShouldNotBeEmpty)
	})

	t.Run("generates unique IDs", func(t *testing.T) {
		id1 := logger.GenerateRequestID()
		id2 := logger.GenerateRequestID()
		id3 := logger.GenerateRequestID()

		assert.NotEqual(t, id1, id2, msgIDsShouldBeUnique)
		assert.NotEqual(t, id1, id3, msgIDsShouldBeUnique)
		assert.NotEqual(t, id2, id3, msgIDsShouldBeUnique)
	})

	t.Run("generates valid UUIDs", func(t *testing.T) {
		id := logger.GenerateRequestID()

		parsedUUID, err := uuid.Parse(id)
		require.NoError(t, err, msgIDShouldBeValidUUID)
		assert.NotEmpty(t, parsedUUID, msgParsedUUIDNotEmpty)
	})

	t.Run("generates UUID v4", func(t *testing.T) {
		id := logger.GenerateRequestID()

		parsedUUID, err := uuid.Parse(id)
		require.NoError(t, err)

		assert.Equal(t, uuid.Version(4), parsedUUID.Version(), msgShouldBeUUIDv4)

		assert.Equal(t, uuid.RFC4122, parsedUUID.Variant(), msgShouldBeRFC4122)
	})
}
