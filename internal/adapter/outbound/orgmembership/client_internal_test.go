package orgmembership

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/gincommon"
)

func TestMain(m *testing.M) {
	// Same TracerProvider + W3C propagator gincommon installs in main() —
	// doRequest injects traceparent via gincommon.InjectTraceContext, which
	// uses that global propagator with no local fallback.
	shutdown := gincommon.InitTracingFromEnv()
	code := m.Run()
	shutdown()
	os.Exit(code)
}

func TestInstrumentedHTTPClient_NonPositiveTimeoutDefaults(t *testing.T) {
	t.Parallel()
	c := instrumentedHTTPClient(0)
	require.NotNil(t, c.Transport)
	assert.Equal(t, 40*time.Millisecond, c.Timeout)
}
