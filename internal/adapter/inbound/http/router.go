// Package http is the minimal internal Gin HTTP server (§1): /healthz,
// /readyz, and a Prometheus /metrics scrape endpoint only. No business
// logic — the authz decision path is exclusively the gRPC adapter.
package http

import (
	"net/http"
	"sync/atomic"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ReadinessProbe reports whether this process has finished startup wiring.
//
// Deliberately NOT a dependency health check: this service is designed to
// keep serving traffic through Valkey-down (bypass) and sibling-down
// (stale-if-error) conditions (§7) — pulling it out of the load balancer's
// rotation exactly when those degraded modes kick in would defeat the point
// of building them. /readyz only answers "has this process finished
// startup", the same thing Kubernetes actually needs to know before routing
// traffic to a new pod.
type ReadinessProbe struct {
	ready atomic.Bool
}

// MarkReady flips the probe to ready. Call once, after cmd/server has
// finished wiring config/cache/clients/consumers.
func (p *ReadinessProbe) MarkReady() { p.ready.Store(true) }

// Ready reports the current readiness state.
func (p *ReadinessProbe) Ready() bool { return p.ready.Load() }

// NewRouter builds the health/readiness/metrics-only Gin engine.
func NewRouter(probe *ReadinessProbe) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	r.GET("/readyz", func(c *gin.Context) {
		if !probe.Ready() {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "starting"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	return r
}
