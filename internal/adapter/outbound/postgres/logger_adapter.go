package postgres

import (
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-pgcommon/pkg/domain"
)

// Logger is the structured logging interface LoggerAdapter wraps. Matches
// gincommon's port.Logger shape (Debug/Info/Warn/Error(msg, fields)) so
// the Zap-backed logger from platform-gincommon/pkg/logger can be passed
// through with no extra adapter at the call site.
type Logger interface {
	Debug(msg string, fields map[string]interface{})
	Info(msg string, fields map[string]interface{})
	Warn(msg string, fields map[string]interface{})
	Error(msg string, fields map[string]interface{})
}

// LoggerAdapter implements platform-pgcommon's pkg/domain.Logger on top of
// a Logger so slow-query / migrate log output (if a pool is ever opened)
// goes through the same Zap sink as the rest of this process.
type LoggerAdapter struct {
	log Logger
}

var _ domain.Logger = LoggerAdapter{}

// NewLoggerAdapter wraps log as a pgcommon domain.Logger.
func NewLoggerAdapter(log Logger) LoggerAdapter {
	return LoggerAdapter{log: log}
}

func (a LoggerAdapter) Debug(msg string, fields ...domain.Field) { a.log.Debug(msg, fieldMap(fields)) }
func (a LoggerAdapter) Info(msg string, fields ...domain.Field)  { a.log.Info(msg, fieldMap(fields)) }
func (a LoggerAdapter) Warn(msg string, fields ...domain.Field)  { a.log.Warn(msg, fieldMap(fields)) }
func (a LoggerAdapter) Error(msg string, fields ...domain.Field) { a.log.Error(msg, fieldMap(fields)) }

func fieldMap(fields []domain.Field) map[string]interface{} {
	m := make(map[string]interface{}, len(fields))
	for _, f := range fields {
		m[f.Key] = f.Value
	}
	return m
}
