package http_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/gincommon"

	httpadapter "github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/inbound/http"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// testGinConfig satisfies gincommon.ObservabilityMiddlewares's requirement
// that ServiceName be non-empty; Logger is left nil, which gincommon
// documents as disabling logging (no-op) rather than panicking.
func testGinConfig() gincommon.Config {
	return gincommon.Config{ServiceName: "iam-authz-enrichment-test"}
}

// testDocsConfig leaves Environment empty (not "production"), so
// DocsConfig.active() is true — the AsyncAPI viewer is mounted the same
// way it would be outside production in a real deployment.
func testDocsConfig() httpadapter.DocsConfig {
	return httpadapter.DocsConfig{}
}

func TestHealthz_AlwaysOK(t *testing.T) {
	t.Parallel()
	router := httpadapter.NewRouter(&httpadapter.ReadinessProbe{}, testGinConfig(), testDocsConfig())

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
}

func TestReadyz_NotReadyBeforeMarkReady(t *testing.T) {
	t.Parallel()
	probe := &httpadapter.ReadinessProbe{}
	router := httpadapter.NewRouter(probe, testGinConfig(), testDocsConfig())

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil)
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.JSONEq(t, `{"status":"starting"}`, rec.Body.String())
}

func TestReadyz_OKAfterMarkReady(t *testing.T) {
	t.Parallel()
	probe := &httpadapter.ReadinessProbe{}
	probe.MarkReady()
	router := httpadapter.NewRouter(probe, testGinConfig(), testDocsConfig())

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil)
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
}

func TestReadinessProbe_DirectMethods(t *testing.T) {
	t.Parallel()
	probe := &httpadapter.ReadinessProbe{}
	assert.False(t, probe.Ready())
	probe.MarkReady()
	assert.True(t, probe.Ready())
}
