package fixtures

import "sync"

// NoopLogger implements usecase.Logger (and consumer.Logger) with no side
// effects — satisfies both packages' identically-shaped local Logger
// interfaces structurally.
type NoopLogger struct{}

func (NoopLogger) Debug(string, map[string]interface{}) {}
func (NoopLogger) Info(string, map[string]interface{})  {}
func (NoopLogger) Warn(string, map[string]interface{})  {}
func (NoopLogger) Error(string, map[string]interface{}) {}

// InfoCapturingLogger captures every Info call. Tests use it to assert
// on structured log emissions without real Zap output.
type InfoCapturingLogger struct {
	mu   sync.Mutex
	msgs []map[string]interface{}
	NoopLogger
}

func (l *InfoCapturingLogger) Info(_ string, fields map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, fields)
}

// InfoLogs returns a snapshot of all captured Info field maps.
func (l *InfoCapturingLogger) InfoLogs() []map[string]interface{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]map[string]interface{}, len(l.msgs))
	copy(out, l.msgs)
	return out
}
