package http_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	httpadapter "github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/inbound/http"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestHealthz_AlwaysOK(t *testing.T) {
	t.Parallel()
	router := httpadapter.NewRouter(&httpadapter.ReadinessProbe{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
}

func TestReadyz_NotReadyBeforeMarkReady(t *testing.T) {
	t.Parallel()
	probe := &httpadapter.ReadinessProbe{}
	router := httpadapter.NewRouter(probe)

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
	router := httpadapter.NewRouter(probe)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil)
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
}

func TestMetrics_ServesPrometheusFormat(t *testing.T) {
	t.Parallel()
	router := httpadapter.NewRouter(&httpadapter.ReadinessProbe{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/plain")
}

func TestReadinessProbe_DirectMethods(t *testing.T) {
	t.Parallel()
	probe := &httpadapter.ReadinessProbe{}
	assert.False(t, probe.Ready())
	probe.MarkReady()
	assert.True(t, probe.Ready())
}
