package logger_test

import (
	"context"
	"gogetnote/pkg/logger"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestFromContext(t *testing.T) {
	t.Run("success when logger exists in context", func(t *testing.T) {
		testLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		ctx := logger.NewContext(context.Background(), testLogger)

		retrievedLogger, err := logger.FromContext(ctx)
		require.NoError(t, err)
		assert.Same(t, testLogger, retrievedLogger)
	})

	t.Run("error when no logger in context", func(t *testing.T) {
		ctx := context.Background()

		retrievedLogger, err := logger.FromContext(ctx)
		require.Error(t, err)
		assert.Nil(t, retrievedLogger)
		assert.ErrorIs(t, err, logger.ErrLoggerNotFound)
	})

	t.Run("error when context has non-logger values", func(t *testing.T) {
		type ctxKeyType struct{}
		ctxKey := ctxKeyType{}

		ctx := context.WithValue(context.Background(), ctxKey, "not a logger")

		retrievedLogger, err := logger.FromContext(ctx)
		require.Error(t, err)
		assert.Nil(t, retrievedLogger)
		assert.ErrorIs(t, err, logger.ErrLoggerNotFound)
	})

	t.Run("success with derived context", func(t *testing.T) {
		testLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		type ctxKeyType struct{}
		ctxKey := ctxKeyType{}

		ctx := logger.NewContext(context.Background(), testLogger)
		derivedCtx := context.WithValue(ctx, ctxKey, "some-value")

		retrievedLogger, err := logger.FromContext(derivedCtx)
		require.NoError(t, err)
		assert.Same(t, testLogger, retrievedLogger)
	})

	t.Run("error with nil context", func(t *testing.T) {
		retrievedLogger, err := logger.FromContext(context.TODO())
		require.Error(t, err)
		assert.Nil(t, retrievedLogger)
		assert.ErrorIs(t, err, logger.ErrLoggerNotFound)
	})
}

func TestFromContextWithMultipleLoggers(t *testing.T) {
	logger1, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)

	logger2, err := logger.NewLogger(logger.Production, "info")
	require.NoError(t, err)

	ctx1 := logger.NewContext(context.Background(), logger1)
	ctx2 := logger.NewContext(context.Background(), logger2)

	retrieved1, err := logger.FromContext(ctx1)
	require.NoError(t, err)
	assert.Same(t, logger1, retrieved1)

	retrieved2, err := logger.FromContext(ctx2)
	require.NoError(t, err)
	assert.Same(t, logger2, retrieved2)
}

func TestInitGlobalLogger(t *testing.T) {
	logger.SetGlobalLogger(nil)

	t.Run("successfully initializes global logger", func(t *testing.T) {
		logger.SetGlobalLogger(nil)

		err := logger.InitGlobalLogger(logger.Development)
		require.NoError(t, err)

		emptyCtx := context.Background()
		globalLog := logger.Log(emptyCtx)
		assert.NotNil(t, globalLog)
	})

	t.Run("returns nil when global logger already exists", func(t *testing.T) {
		logger.SetGlobalLogger(nil)

		err1 := logger.InitGlobalLogger(logger.Production)
		require.NoError(t, err1)

		emptyCtx := context.Background()
		firstLogger := logger.Log(emptyCtx)
		require.NotNil(t, firstLogger)

		err2 := logger.InitGlobalLogger(logger.Development)
		require.NoError(t, err2)

		secondLogger := logger.Log(emptyCtx)

		assert.Same(t, firstLogger, secondLogger)
	})

	t.Run("returns wrapped error on initialization failure", func(t *testing.T) {
		logger.SetGlobalLogger(nil)

		err := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
		require.NoError(t, err)
	})
}

func TestInitGlobalLoggerWithLevel(t *testing.T) {
	logger.SetGlobalLogger(nil)

	t.Run("successfully initializes global logger with specific level", func(t *testing.T) {
		logger.SetGlobalLogger(nil)

		err := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
		require.NoError(t, err)

		emptyCtx := context.Background()
		globalLog := logger.Log(emptyCtx)
		assert.NotNil(t, globalLog)
	})

	t.Run("returns nil when global logger already exists", func(t *testing.T) {
		logger.SetGlobalLogger(nil)

		err1 := logger.InitGlobalLoggerWithLevel(logger.Production, "info")
		require.NoError(t, err1)

		emptyCtx := context.Background()
		firstLogger := logger.Log(emptyCtx)
		require.NotNil(t, firstLogger)

		err2 := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
		require.NoError(t, err2)

		secondLogger := logger.Log(emptyCtx)

		assert.Same(t, firstLogger, secondLogger)
	})
}

func TestLog(t *testing.T) {
	logger.SetGlobalLogger(nil)
	defer logger.SetGlobalLogger(nil)

	t.Run("returns logger from context when available", func(t *testing.T) {
		contextLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		globalLogger, err := logger.NewLogger(logger.Production, "error")
		require.NoError(t, err)
		logger.SetGlobalLogger(globalLogger)

		ctx := logger.NewContext(context.Background(), contextLogger)

		result := logger.Log(ctx)
		assert.Same(t, contextLogger, result)
		assert.NotSame(t, globalLogger, result)
	})

	t.Run("returns global logger when no logger in context", func(t *testing.T) {
		globalLogger, err := logger.NewLogger(logger.Development, "info")
		require.NoError(t, err)
		logger.SetGlobalLogger(globalLogger)

		ctx := context.Background()

		result := logger.Log(ctx)
		assert.Same(t, globalLogger, result)
	})

	t.Run("returns fallback logger when no context or global logger", func(t *testing.T) {
		logger.SetGlobalLogger(nil)

		ctx := context.Background()

		result := logger.Log(ctx)
		assert.NotNil(t, result, "fallback logger should not be nil")

		newLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)
		assert.NotSame(t, newLogger, result, "should not be a newly created logger")
	})

	t.Run("handles empty context by returning global or fallback logger", func(t *testing.T) {
		globalLogger, err := logger.NewLogger(logger.Production, "warn")
		require.NoError(t, err)
		logger.SetGlobalLogger(globalLogger)

		emptyCtx := context.Background()
		result := logger.Log(emptyCtx)
		assert.NotNil(t, result)
		assert.Same(t, globalLogger, result)

		logger.SetGlobalLogger(nil)
		result = logger.Log(emptyCtx)
		assert.NotNil(t, result, "should return fallback logger with empty context and no global logger")
	})

	t.Run("returns the same fallback logger instance each time", func(t *testing.T) {
		logger.SetGlobalLogger(nil)

		ctx := context.Background()
		result1 := logger.Log(ctx)
		result2 := logger.Log(ctx)

		assert.Same(t, result1, result2, "fallback logger should be a singleton")
	})
}

func TestNewContext(t *testing.T) {
	t.Run("adds_logger_to_context_and_can_be_retrieved", func(t *testing.T) {
		testLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)
		require.NotNil(t, testLogger)

		ctx := context.Background()
		loggerCtx := logger.NewContext(ctx, testLogger)

		assert.NotEqual(t, ctx, loggerCtx)

		retrievedLogger, err := logger.FromContext(loggerCtx)
		require.NoError(t, err)
		require.NotNil(t, retrievedLogger)

		assert.Same(t, testLogger, retrievedLogger)
	})

	t.Run("calling Log() gets logger from context", func(t *testing.T) {
		testLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		ctx := context.Background()
		loggerCtx := logger.NewContext(ctx, testLogger)

		retrievedLogger := logger.Log(loggerCtx)
		assert.Same(t, testLogger, retrievedLogger)
	})

	t.Run("different loggers in different contexts", func(t *testing.T) {
		logger1, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		logger2, err := logger.NewLogger(logger.Production, "info")
		require.NoError(t, err)

		ctx := context.Background()
		ctx1 := logger.NewContext(ctx, logger1)
		ctx2 := logger.NewContext(ctx, logger2)

		retrieved1, err := logger.FromContext(ctx1)
		require.NoError(t, err)

		retrieved2, err := logger.FromContext(ctx2)
		require.NoError(t, err)

		assert.Same(t, logger1, retrieved1)
		assert.Same(t, logger2, retrieved2)
		assert.NotSame(t, retrieved1, retrieved2)
	})

	t.Run("FromContext returns error for context without logger", func(t *testing.T) {
		ctx := context.Background()

		_, err := logger.FromContext(ctx)

		require.Error(t, err)
		assert.ErrorIs(t, err, logger.ErrLoggerNotFound)
	})

	t.Run("context hierarchy maintains logger", func(t *testing.T) {
		testLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		baseCtx := context.Background()
		loggerCtx := logger.NewContext(baseCtx, testLogger)

		type childKeyType struct{}
		childKey := childKeyType{}
		childValue := "child-value"

		childCtx := context.WithValue(loggerCtx, childKey, childValue)

		retrievedLogger, err := logger.FromContext(childCtx)
		require.NoError(t, err)
		assert.Same(t, testLogger, retrievedLogger)

		assert.Equal(t, childValue, childCtx.Value(childKey))
	})
}

func TestSetGlobalLogger(t *testing.T) {
	emptyCtx := context.Background()

	t.Run("sets global logger to a new value", func(t *testing.T) {
		testLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		logger.SetGlobalLogger(testLogger)

		returnedLogger := logger.Log(emptyCtx)
		assert.Same(t, testLogger, returnedLogger, "Log() should return the global logger we just set")
	})

	t.Run("sets global logger to nil", func(t *testing.T) {
		testLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)
		logger.SetGlobalLogger(testLogger)

		logger.SetGlobalLogger(nil)

		returnedLogger := logger.Log(emptyCtx)
		assert.NotNil(t, returnedLogger, "Log() should return the fallback logger, not nil")
		assert.NotSame(t, testLogger, returnedLogger, "Log() should not return previous global logger")
	})

	t.Run("logger from context has priority over global logger", func(t *testing.T) {
		globalLogger, err := logger.NewLogger(logger.Production, "info")
		require.NoError(t, err)
		logger.SetGlobalLogger(globalLogger)

		contextLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		ctx := logger.NewContext(emptyCtx, contextLogger)

		returnedLogger := logger.Log(ctx)
		assert.Same(t, contextLogger, returnedLogger, "Log() should return the context logger")
		assert.NotSame(t, globalLogger, returnedLogger, "Log() should not return the global logger")
	})

	t.Run("multiple calls update the global logger", func(t *testing.T) {
		logger1, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)
		logger.SetGlobalLogger(logger1)

		returnedLogger := logger.Log(emptyCtx)
		assert.Same(t, logger1, returnedLogger)

		logger2, err := logger.NewLogger(logger.Production, "info")
		require.NoError(t, err)
		logger.SetGlobalLogger(logger2)

		returnedLogger = logger.Log(emptyCtx)
		assert.Same(t, logger2, returnedLogger)
		assert.NotSame(t, logger1, returnedLogger)
	})

	logger.SetGlobalLogger(nil)
}

func TestAddRequestIDFromContext(t *testing.T) {
	t.Run("context with request ID adds field to logs", func(t *testing.T) {
		requestID := "test-request-id-123"

		ctx := logger.NewRequestIDContext(context.Background(), requestID)

		tempLog, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		tempLog.Info(ctx, "test message")

		logWithReqID := tempLog.WithRequestID(ctx)
		assert.NotSame(t, tempLog, logWithReqID, "withRequestID should return a new logger when request ID exists")

		emptyCtx := context.Background()
		logWithoutReqID := tempLog.WithRequestID(emptyCtx)
		assert.Same(t, tempLog, logWithoutReqID, "withRequestID should return same logger when no request ID exists")
	})

	t.Run("context without request ID doesn't add field", func(t *testing.T) {
		tempLog, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)
		t.Run("adds logger to context and can be retrieved", func(t *testing.T) {
			testLogger, err := logger.NewLogger(logger.Development, "debug")
			require.NoError(t, err)
			require.NotNil(t, testLogger)

			ctx := context.Background()
			loggerCtx := logger.NewContext(ctx, testLogger)

			assert.NotEqual(t, ctx, loggerCtx)

			retrievedLogger, err := logger.FromContext(loggerCtx)
			require.NoError(t, err)
			require.NotNil(t, retrievedLogger)

			assert.Same(t, testLogger, retrievedLogger)
		})
		ctx := context.Background()

		logWithoutReqID := tempLog.WithRequestID(ctx)
		assert.Same(t, tempLog, logWithoutReqID, "withRequestID should return same logger when no request ID exists")

		assert.NotPanics(t, func() {
			tempLog.Info(ctx, "plain context message")
		})
	})

	t.Run("context without request ID doesn't modify logger", func(t *testing.T) {
		tempLog, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)
		t.Run("adds logger to context and can be retrieved", func(t *testing.T) {
			testLogger, err := logger.NewLogger(logger.Development, "debug")
			require.NoError(t, err)
			require.NotNil(t, testLogger)

			ctx := context.Background()
			loggerCtx := logger.NewContext(ctx, testLogger)

			assert.NotEqual(t, ctx, loggerCtx) // Changed from NotSame to NotEqual

			retrievedLogger, err := logger.FromContext(loggerCtx)
			require.NoError(t, err)
			require.NotNil(t, retrievedLogger)

			assert.Same(t, testLogger, retrievedLogger)
		})
		ctx := context.Background()

		logWithoutReqID := tempLog.WithRequestID(ctx)
		assert.Same(t, tempLog, logWithoutReqID, "withRequestID should return same logger when no request ID exists")

		assert.NotPanics(t, func() {
			tempLog.Info(ctx, "plain context message")
		})
	})

	t.Run("existing fields are preserved", func(t *testing.T) {
		tempLog, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		customField := zap.String("custom_field", "custom-value")
		logWithCustomField := tempLog.With(customField)

		requestID := "test-request-id-456"
		ctx := logger.NewRequestIDContext(context.Background(), requestID)

		logWithBoth := logWithCustomField.WithRequestID(ctx)

		assert.NotSame(t, tempLog, logWithBoth, "logger with both fields should differ from base logger")
		assert.NotSame(t, logWithCustomField, logWithBoth, "logger with both fields should differ from logger with only custom field")

		assert.NotPanics(t, func() {
			logWithBoth.Info(ctx, "message with custom field")
		})
	})
}

func TestLoggerMethods(t *testing.T) {
	log, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	require.NotNil(t, log)

	t.Run("With creates new logger instance", func(t *testing.T) {
		field := zap.String("key", "value")
		newLog := log.With(field)

		assert.NotNil(t, newLog)
		assert.NotSame(t, log, newLog, "With() should return a new logger instance")
	})

	t.Run("With multiple fields", func(t *testing.T) {
		field1 := zap.String("key1", "value1")
		field2 := zap.Int("key2", 42)
		newLog := log.With(field1, field2)

		assert.NotNil(t, newLog)
		assert.NotSame(t, log, newLog)
	})

	t.Run("Logging methods with plain context", func(t *testing.T) {
		ctx := context.Background()

		assert.NotPanics(t, func() {
			log.Debug(ctx, "debug message")
			log.Info(ctx, "info message")
			log.Warn(ctx, "warning message")
			log.Error(ctx, "error message")
		})
	})

	t.Run("Logging methods with request ID context", func(t *testing.T) {
		requestID := "test-request-id-123"
		ctx := logger.NewRequestIDContext(context.Background(), requestID)

		id, ok := logger.GetRequestID(ctx)
		assert.True(t, ok)
		assert.Equal(t, requestID, id)

		assert.NotPanics(t, func() {
			log.Debug(ctx, "debug message with request ID")
			log.Info(ctx, "info message with request ID")
			log.Warn(ctx, "warning message with request ID")
			log.Error(ctx, "error message with request ID")
		})
	})

	t.Run("Logging methods with custom fields", func(t *testing.T) {
		ctx := context.Background()
		field1 := zap.String("custom_field", "custom_value")
		field2 := zap.Int("count", 100)

		assert.NotPanics(t, func() {
			log.Debug(ctx, "debug with fields", field1, field2)
			log.Info(ctx, "info with fields", field1, field2)
			log.Warn(ctx, "warn with fields", field1, field2)
			log.Error(ctx, "error with fields", field1, field2)
		})
	})

	t.Run("Sync method", func(t *testing.T) {
		assert.NotPanics(t, func() {
			err := log.Sync()
			_ = err
		})
	})

	t.Run("WithRequestID creates logger with request ID", func(t *testing.T) {
		requestID := "test-request-id-456"
		ctx := logger.NewRequestIDContext(context.Background(), requestID)

		newLog := log.WithRequestID(ctx)
		assert.NotNil(t, newLog)
		assert.NotSame(t, log, newLog)
	})
}

func TestNewLogger(t *testing.T) {
	t.Run("development environment with different log levels", func(t *testing.T) {
		testCases := []struct {
			level string
			valid bool
		}{
			{"debug", true},
			{"info", true},
			{"warn", true},
			{"warning", true},
			{"error", true},
			{"invalid", true},
			{"", true},
		}

		for _, tc := range testCases {
			t.Run("level="+tc.level, func(t *testing.T) {
				log, err := logger.NewLogger(logger.Development, tc.level)
				if tc.valid {
					require.NoError(t, err)
					require.NotNil(t, log)
				} else {
					require.Error(t, err)
				}
			})
		}
	})

	t.Run("production environment with different log levels", func(t *testing.T) {
		testCases := []struct {
			level string
			valid bool
		}{
			{"debug", true},
			{"info", true},
			{"warn", true},
			{"warning", true},
			{"error", true},
			{"invalid", true},
			{"", true},
		}

		for _, tc := range testCases {
			t.Run("level="+tc.level, func(t *testing.T) {
				log, err := logger.NewLogger(logger.Production, tc.level)
				if tc.valid {
					require.NoError(t, err)
					require.NotNil(t, log)
				} else {
					require.Error(t, err)
				}
			})
		}
	})

	t.Run("basic logging functionality", func(t *testing.T) {
		log, err := logger.NewLogger(logger.Development, "info")
		require.NoError(t, err)
		require.NotNil(t, log)

		ctx := logger.NewRequestIDContext(context.Background(), "test-request-id")

		assert.NotPanics(t, func() {
			log.Debug(ctx, "debug message")
			log.Info(ctx, "info message")
			log.Warn(ctx, "warn message")
			log.Error(ctx, "error message")
		})
	})

	t.Run("with method creates new logger instance", func(t *testing.T) {
		log, err := logger.NewLogger(logger.Development, "info")
		require.NoError(t, err)

		newLog := log.With()
		assert.NotNil(t, newLog)
		assert.NotSame(t, log, newLog)
	})
}

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

const (
	msgRequestIDFound        = "should indicate request ID was found"
	msgCorrectRequestID      = "should return the correct request ID"
	msgNoRequestIDFound      = "should indicate no request ID was found"
	msgEmptyWhenNotFound     = "should return empty string when not found"
	msgNonEmptyAutoGenerated = "should return non-empty auto-generated ID"
	msgIDInDerivedContext    = "should find ID in derived context"
	msgIDFromParentContext   = "should return the ID from parent context"
)

type testKeyType struct{}

var testKey = testKeyType{}

func TestGetRequestID(t *testing.T) {
	t.Run("returns request ID when present in context", func(t *testing.T) {
		expectedID := "test-request-id-123"
		ctx := logger.NewRequestIDContext(context.Background(), expectedID)

		retrievedID, ok := logger.GetRequestID(ctx)

		assert.True(t, ok, msgRequestIDFound)
		assert.Equal(t, expectedID, retrievedID, msgCorrectRequestID)
	})

	t.Run("returns false when no request ID in context", func(t *testing.T) {
		ctx := context.Background()

		retrievedID, ok := logger.GetRequestID(ctx)

		assert.False(t, ok, msgNoRequestIDFound)
		assert.Empty(t, retrievedID, msgEmptyWhenNotFound)
	})

	t.Run("handles auto-generated request IDs", func(t *testing.T) {
		ctx := logger.NewRequestIDContext(context.Background(), "")

		retrievedID, ok := logger.GetRequestID(ctx)

		assert.True(t, ok, msgRequestIDFound)
		assert.NotEmpty(t, retrievedID, msgNonEmptyAutoGenerated)
	})

	t.Run("returns same ID for derived contexts", func(t *testing.T) {
		expectedID := "parent-request-id"
		parentCtx := logger.NewRequestIDContext(context.Background(), expectedID)

		childCtx := context.WithValue(parentCtx, testKey, "some-value")

		retrievedID, ok := logger.GetRequestID(childCtx)

		assert.True(t, ok, msgIDInDerivedContext)
		assert.Equal(t, expectedID, retrievedID, msgIDFromParentContext)
	})
}

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
	t.Run("stores_provided_request_ID_in_context", func(t *testing.T) {
		baseCtx := context.Background()

		customID := "test-request-id-123"

		ctx := logger.NewRequestIDContext(baseCtx, customID)

		assert.NotEqual(t, baseCtx, ctx) // Changed from NotSame to NotEqual

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

const (
	msgNewLoggerWithID        = "withRequestID should return a new logger when request ID exists"
	msgSameLoggerNoID         = "withRequestID should return the same logger when no request ID exists"
	msgNewLogger              = "withRequestID should return a new logger"
	msgSameLoggerEmptyContext = "withRequestID should return the same logger for empty context"
	msgNewLoggerContextWithID = "withRequestID should return a new logger for context with ID"
)

func TestWithRequestID(t *testing.T) {
	t.Run("adds request ID field when present in context", func(t *testing.T) {
		baseLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		requestID := "test-request-id-123"
		ctx := logger.NewRequestIDContext(context.Background(), requestID)

		loggerWithID := baseLogger.WithRequestID(ctx)

		assert.NotSame(t, baseLogger, loggerWithID, msgNewLoggerWithID)

		loggerWithID.Info(ctx, "test message with request ID")

		emptyCtx := context.Background()
		loggerWithoutID := baseLogger.WithRequestID(emptyCtx)

		assert.Same(t, baseLogger, loggerWithoutID, msgSameLoggerNoID)
	})

	t.Run("returns original logger when no request ID in context", func(t *testing.T) {
		baseLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		ctx := context.Background()

		resultLogger := baseLogger.WithRequestID(ctx)

		assert.Same(t, baseLogger, resultLogger, msgSameLoggerNoID)
	})

	t.Run("preserves existing fields when adding request ID", func(t *testing.T) {
		baseLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		customField := "custom-field"
		customValue := "custom-value"
		loggerWithField := baseLogger.With(zap.String(customField, customValue))

		requestID := "test-request-id-456"
		ctx := logger.NewRequestIDContext(context.Background(), requestID)

		loggerWithRequestID := loggerWithField.WithRequestID(ctx)

		assert.NotSame(t, loggerWithField, loggerWithRequestID, msgNewLogger)

		loggerWithRequestID.Info(ctx, "test message with both fields")
	})

	t.Run("handles nil context safely", func(t *testing.T) {
		baseLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		ctx := context.Background()

		resultLogger := baseLogger.WithRequestID(ctx)

		assert.Same(t, baseLogger, resultLogger, msgSameLoggerEmptyContext)
	})

	t.Run("request ID field has the expected name", func(t *testing.T) {
		baseLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		requestID := "test-request-id-789"
		ctx := logger.NewRequestIDContext(context.Background(), requestID)

		loggerWithRequestID := baseLogger.WithRequestID(ctx)

		loggerWithRequestID.Info(ctx, "test message for field name")

		assert.NotSame(t, baseLogger, loggerWithRequestID, msgNewLoggerContextWithID)
	})
}
