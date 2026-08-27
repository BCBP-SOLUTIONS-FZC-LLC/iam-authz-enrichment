// Package http is the minimal internal Gin HTTP server (§1): /healthz and
// /readyz, plus (opt-in outside dev, DocsConfig-gated) the AsyncAPI event-
// contract viewer at /asyncapi and /asyncapi.yaml (asyncapi.go). No
// business logic either way — the authz decision path is exclusively the
// gRPC adapter. /metrics is served separately, on its own dedicated port
// (see cmd/server/main.go's metricsServer).
package http

import (
	"net/http"
	"sync/atomic"

	"github.com/gin-gonic/gin"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/gincommon"
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

// DocsConfig controls whether — and how — the AsyncAPI viewer doc surface
// is exposed. Outside production it's always on; in production it's opt-in
// via Enabled and, if AuthToken is set, gated behind a bearer token so the
// event contract isn't exposed to the open internet by default. Mirrors
// iam-org-membership's/iam-tender-acl's identical DocsConfig — this
// service has no Swagger half (no business HTTP API to document), so only
// the AsyncAPI routes are wired below.
type DocsConfig struct {
	Environment string
	Enabled     bool
	AuthToken   string
}

func (d DocsConfig) active() bool {
	return d.Environment != "production" || d.Enabled
}

// NewRouter builds the health/readiness-only Gin engine, plus (when active)
// the AsyncAPI event-contract viewer. ginCfg wires platform-gincommon's
// ObservabilityMiddlewares (panic recovery, request-ID, tracing,
// correlation, metrics, logging) — the same fleet-wide stack
// iam-org-membership and iam-user-profile put in front of their Gin
// routers, so every route here gets logged and traced like every other
// service's HTTP surface instead of falling through gin.Recovery() alone.
func NewRouter(probe *ReadinessProbe, ginCfg gincommon.Config, docs DocsConfig) *gin.Engine {
	r := gin.New()
	r.Use(gincommon.ObservabilityMiddlewares(ginCfg)...)

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

	registerDocsRoutes(r, docs)

	return r
}

// registerDocsRoutes wires the AsyncAPI viewer (asyncapi.go): api/
// asyncapi.yaml, embedded at compile time (api/embed.go) so it needs no
// file present at runtime, rendered as a browsable HTML catalog at
// GET /asyncapi, plus the raw spec verbatim at GET /asyncapi.yaml. Ported
// from iam-tender-acl's identical registerDocsRoutes, minus its Swagger
// half — this service has no business HTTP API to document with one.
// Outside production both routes are always mounted; in production
// they're opt-in via DocsConfig.Enabled and, if AuthToken is set, gated
// behind the same bearer token so the event contract isn't exposed to the
// open internet by default.
func registerDocsRoutes(engine *gin.Engine, docs DocsConfig) {
	if !docs.active() {
		return
	}
	asyncGroup := engine.Group("")
	if docs.Environment == "production" && docs.AuthToken != "" {
		asyncGroup.Use(docsAuthMiddleware(docs.AuthToken))
	}
	asyncGroup.Use(envMiddleware(docs.Environment))
	asyncGroup.GET("/asyncapi", AsyncAPIHandler)
	asyncGroup.GET("/asyncapi.yaml", AsyncAPIYAMLHandler)
}

// docsAuthMiddleware requires an exact `Authorization: Bearer <token>`
// match before letting a request through to the AsyncAPI viewer.
func docsAuthMiddleware(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("Authorization") != "Bearer "+token {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}
