package postgres

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-pgcommon/v2/pkg/domain"
)

type recordingLogger struct {
	level  string
	msg    string
	fields map[string]interface{}
}

func (r *recordingLogger) Debug(msg string, fields map[string]interface{}) {
	r.level, r.msg, r.fields = "debug", msg, fields
}
func (r *recordingLogger) Info(msg string, fields map[string]interface{}) {
	r.level, r.msg, r.fields = "info", msg, fields
}
func (r *recordingLogger) Warn(msg string, fields map[string]interface{}) {
	r.level, r.msg, r.fields = "warn", msg, fields
}
func (r *recordingLogger) Error(msg string, fields map[string]interface{}) {
	r.level, r.msg, r.fields = "error", msg, fields
}

func TestLoggerAdapter_Warn_ConvertsFieldsToMap(t *testing.T) {
	rec := &recordingLogger{}
	adapter := NewLoggerAdapter(rec)

	adapter.Warn("slow query", domain.Field{Key: "query", Value: "SELECT"}, domain.Field{Key: "duration_ms", Value: int64(250)})

	assert.Equal(t, "warn", rec.level)
	assert.Equal(t, "slow query", rec.msg)
	require.NotNil(t, rec.fields)
	assert.Equal(t, "SELECT", rec.fields["query"])
	assert.Equal(t, int64(250), rec.fields["duration_ms"])
}

func TestLoggerAdapter_AllLevels_DelegateToMatchingMethod(t *testing.T) {
	rec := &recordingLogger{}
	adapter := NewLoggerAdapter(rec)

	adapter.Debug("d")
	assert.Equal(t, "debug", rec.level)

	adapter.Info("i")
	assert.Equal(t, "info", rec.level)

	adapter.Error("e")
	assert.Equal(t, "error", rec.level)
}

func TestLoggerAdapter_NoFields_ProducesEmptyMap(t *testing.T) {
	rec := &recordingLogger{}
	adapter := NewLoggerAdapter(rec)

	adapter.Info("no fields")

	assert.NotNil(t, rec.fields)
	assert.Empty(t, rec.fields)
}
