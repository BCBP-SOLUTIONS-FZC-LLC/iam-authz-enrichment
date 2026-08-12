package fixtures

// NoopLogger implements usecase.Logger (and consumer.Logger) with no side
// effects — satisfies both packages' identically-shaped local Logger
// interfaces structurally.
type NoopLogger struct{}

func (NoopLogger) Debug(string, map[string]interface{}) {}
func (NoopLogger) Info(string, map[string]interface{})  {}
func (NoopLogger) Warn(string, map[string]interface{})  {}
func (NoopLogger) Error(string, map[string]interface{}) {}
