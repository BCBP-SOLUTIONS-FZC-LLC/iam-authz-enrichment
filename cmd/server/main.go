// Command server is the iam-authz-enrichment entrypoint: it wires config,
// starts the gRPC ext_authz server, the health/readiness/metrics HTTP
// server, and the five SQS consumers (§1).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2/pkg/events"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/gincommon"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/grpccommon"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/logger"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-pgcommon/v2/pkg/pgmetrics"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/inbound/consumer"
	grpcadapter "github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/inbound/grpc"
	httpadapter "github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/inbound/http"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/outbound/metrics"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/outbound/orgmembership"
	pgadapter "github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/outbound/postgres"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/outbound/valkey"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/config"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
)

// buildVersion is overridden at build time via -ldflags (see Dockerfile/Makefile).
var buildVersion = "dev"

// grpcGracefulStopTimeout bounds how long shutdown waits for
// grpcServer.GracefulStop() to drain in-flight RPCs/connections before
// forcing a hard Stop(). GracefulStop otherwise blocks unconditionally — a
// single wedged Envoy connection or a Check() call stuck on a hanging
// downstream call would stall every shutdown step after it (HTTP shutdown,
// consumer drain, cache.Close()) until Kubernetes' own
// terminationGracePeriodSeconds expires and SIGKILLs the pod, skipping the
// graceful consumer drain entirely instead of just this one step.
//
// 10s, not a rounder 30s: it shares deploy/helm/values.yaml's 60s
// terminationGracePeriodSeconds with httpShutdownTimeout (10s) and the SQS
// consumers' own drain window (platform-events default 30s+5s margin,
// stopped concurrently, §11) — 10+10+35 = 55s leaves a 5s margin instead of
// eating the whole budget on the phase least likely to ever need it (a
// Check() call is sub-100ms in the overwhelming common case).
const grpcGracefulStopTimeout = 10 * time.Second

// httpShutdownTimeout bounds the health/readiness/AsyncAPI HTTP server's and
// the metrics server's Shutdown() calls — see grpcGracefulStopTimeout's
// comment for why this and the other two shutdown phases are each kept
// well below terminationGracePeriodSeconds/3 rather than a generic 30s:
// neither server holds long-lived business connections (probes and scrapes
// are all sub-millisecond, single-shot requests), so 30s of headroom here
// was budget taken from the phase that actually needs it — the SQS
// consumer drain.
const httpShutdownTimeout = 10 * time.Second

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// Logger first, matching iam-user-profile / iam-org-membership: Zap via
	// platform-gincommon so every subsequent startup failure (config, listen,
	// consumers) goes through the same sink instead of stdlib log.Fatal.
	appEnv := config.ResolveAppEnv()
	if appEnv != "dev" {
		gin.SetMode(gin.ReleaseMode)
	}
	appLog, err := logger.NewLogger(appEnv)
	if err != nil {
		return fmt.Errorf("build logger: %w", err)
	}

	cfg, err := config.Load()
	if err != nil {
		appLog.Error("load config", map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("load config: %w", err)
	}
	appLog.Info("starting", map[string]interface{}{
		"service": cfg.AppName, "version": buildVersion, "env": cfg.AppEnv,
	})

	// SHARED_REALM_ISSUER is legitimately optional — ResolveTenant falls
	// back to RealmTenantMapSeed for dedicated-realm-only platforms (see
	// tenant_resolve.go) — so this is a warning, not the hard startup
	// failure config.Load() applies to ORG_MEMBERSHIP_BASE_URL. But BOTH
	// empty outside dev means there is no tenant-resolution path at all:
	// every request will resolve to DENY_MALFORMED_IDENTITY.
	if cfg.AppEnv != "dev" && cfg.SharedRealmIssuer == "" && len(cfg.RealmTenantMapSeed) == 0 {
		appLog.Warn("no tenant-resolution path configured — every request will get DENY_MALFORMED_IDENTITY until SHARED_REALM_ISSUER is set or a TenantConverted/TenantRealmReady event seeds the realm map", nil)
	}

	// Align the env vars the platform libraries read directly (APP_NAME,
	// OTEL_SERVICE_NAME — platform-events' consumer spans — and BUILD_VERSION)
	// with this process's identity, so a deployment that sets only APP_NAME
	// (as the Helm chart does) still gets matching trace/metric labels — same
	// ensureGincommonEnv pattern as iam-org-membership / iam-delegation.
	if os.Getenv("APP_NAME") == "" {
		_ = os.Setenv("APP_NAME", cfg.AppName)
	}
	if os.Getenv("OTEL_SERVICE_NAME") == "" {
		_ = os.Setenv("OTEL_SERVICE_NAME", cfg.AppName)
	}
	if os.Getenv("BUILD_VERSION") == "" && buildVersion != "" {
		_ = os.Setenv("BUILD_VERSION", buildVersion)
	}

	// 2. Tracing — always install gincommon's TracerProvider so in-process
	// spans (authz.lookup_cache / i8_call / …) and outbound W3C
	// traceparent injection get a real provider even when
	// OTEL_EXPORTER_OTLP_ENDPOINT is unset (dev; set it to "none" to skip
	// export entirely). InitTracingWithConfig takes the same identity as
	// ginCfg/grpcCfg below, so trace resources (service.namespace,
	// deployment.environment.name) can't disagree with metric labels —
	// InitTracingFromEnv resolved domain/environment from the environment on
	// its own. Same call as iam-org-membership. Interceptor/middleware
	// EnsureInitTelemetry is then a no-op. Flush: shutdownTracing then
	// grpccommon.Shutdown (this process is gRPC-primary; it is the same
	// OTel+Zap flush as gincommon.Shutdown).
	shutdownTracing, err := gincommon.InitTracingWithConfig(gincommon.TracingConfig{
		ServiceName:  cfg.AppName,
		BuildVersion: buildVersion,
		Domain:       observabilityDomain,
		Environment:  cfg.AppEnv,
		Logger:       appLog,
	})
	if err != nil {
		appLog.Error("init tracing", map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("init tracing: %w", err)
	}

	// Observability identity (Enterprise Platform Observability Standard):
	// domain "iam" is fixed for this service; OBSERVABILITY_DOMAIN (set in
	// the Helm values / compose / .env-example) is only the fallback
	// gincommon reads when Config.Domain is empty. The environment comes
	// from APP_ENV and must be one of local/dev/test/staging/prod —
	// gincommon panics at startup on anything else (e.g. "production").
	ginCfg := gincommon.Config{
		Logger:       appLog,
		ServiceName:  cfg.AppName,
		BuildVersion: buildVersion,
		Domain:       observabilityDomain,
		Environment:  cfg.AppEnv,
	}
	grpcCfg := grpccommon.Config{
		ServiceName:  cfg.AppName,
		BuildVersion: buildVersion,
		Logger:       appLog,
		Domain:       observabilityDomain,
		Environment:  cfg.AppEnv,
	}

	// ObservabilityMiddlewares is gincommon's public metrics-init API. Call
	// it here (before any collector registration) so iam_authz_enrichment_* and
	// platform-events metrics land on gincommon.MetricsRegisterer with
	// matching {domain, service, environment} const labels — same order as
	// iam-org-membership / iam-user-profile. NewRouter applies the same
	// middleware slice; gincommon's metrics init is first-call-wins.
	_ = gincommon.ObservabilityMiddlewares(ginCfg)

	// 3. Metrics — business collectors + platform-events / platform-pgcommon
	// Tier 1 collectors, all on gincommon's registerer (the same /metrics
	// scrape as HTTP/gRPC interceptor series), with the identity gincommon
	// resolved so every library labels the same {domain, service,
	// environment}. pgcommon's identity is initialised before any pool
	// would be created (this service creates none today — HLD §5.4).
	recorder, err := metrics.New(gincommon.MetricsRegisterer())
	if err != nil {
		appLog.Error("init business metrics", map[string]interface{}{"error": err.Error()})
		shutdownTracing()
		return fmt.Errorf("init business metrics: %w", err)
	}
	if err := initLibraryMetrics(appLog); err != nil {
		appLog.Error("init platform metrics", map[string]interface{}{"error": err.Error()})
		shutdownTracing()
		return fmt.Errorf("init platform metrics: %w", err)
	}

	// Database config — same ConfigFromEnv / DSNFromEnv / Zap logger /
	// gincommon TracerProvider path as iam-user-profile / iam-org-membership.
	// This service has no schema (HLD §5.4), so NewPool / migrate / outbox
	// are never started. OpenPool remains the only constructor a future
	// schema is allowed to use.
	pgCfg, pgWarnings := pgadapter.PoolConfig(appLog, cfg.AppName)
	for _, w := range pgWarnings {
		if pgCfg.DSN == "" && w.Key == "PG_USER/PG_DBNAME" {
			continue
		}
		appLog.Warn("postgres config warning", map[string]interface{}{"key": w.Key, "reason": w.Reason})
	}
	if pgCfg.DSN != "" {
		appLog.Warn("postgres DSN is set but iam-authz-enrichment has no database (HLD §5.4) — platform-pgcommon NewPool / migrate / outbox not started", nil)
	}
	if os.Getenv("MIGRATION_DATABASE_URL") != "" || os.Getenv("SYSTEM_DATABASE_URL") != "" {
		appLog.Warn("MIGRATION_DATABASE_URL/SYSTEM_DATABASE_URL is set but iam-authz-enrichment has no database — migrate / sysPool not started", nil)
	}

	// 4. Cache.
	cache := valkey.New(valkey.Config{
		Addr:               cfg.ValkeyURL,
		DialTimeout:        cfg.ValkeyDialTimeout,
		ReadTimeout:        cfg.ValkeyReadTimeout,
		WriteTimeout:       cfg.ValkeyWriteTimeout,
		CtxTTL:             cfg.AeCtxTTL,
		CtxJitter:          cfg.AeCtxJitter,
		TenderACLTTL:       cfg.TenderACLTTL,
		NegativeTTL:        cfg.NegativeCacheTTL,
		ProcessedTTL:       cfg.ProcessedEventTTL,
		StaleIfErrorMaxAge: cfg.StaleIfErrorMaxAge,
	})
	// eventCache: same Valkey, own pool, VALKEY_EVENT_TIMEOUT socket timeouts
	// — for everything the SQS consumers write (see Cache.WithTimeouts). The
	// request path keeps cache's single-digit-ms timeouts.
	eventCache := cache.WithTimeouts(cfg.ValkeyEventTimeout, cfg.ValkeyEventTimeout, cfg.ValkeyEventTimeout)
	facts := factStore{Cache: cache, writes: eventCache}

	// 5. Org & Membership + iam-tender-acl client (I-12/GetTenderACL moved to
	// the latter in ADR-0007 Wave 3 Phase 4 — see orgmembership.New's doc
	// comment).
	orgClient := orgmembership.New(cfg.OrgMembershipBaseURL, cfg.OrgMembershipTimeout, cfg.TenderACLBaseURL, cfg.TenderACLTimeout)

	// 6. In-process policy state + usecase layer.
	realmMap := usecase.NewRealmMap(cfg.RealmTenantMapSeed, cfg.RealmNegativeTTL)
	realmMap.BindStore(facts)
	if err := realmMap.PersistSeed(context.Background()); err != nil {
		appLog.Warn("failed to persist realm-map seed to Valkey — other replicas will not see seed mappings until they load the same env", map[string]interface{}{"error": err.Error()})
	}
	restricted := usecase.NewRestrictedTenderSet(cfg.RestrictedNegativeTTL)
	restricted.BindStore(facts)
	checker := usecase.NewChecker(cache, orgClient, realmMap, restricted, appLog, recorder, usecase.CheckerConfig{
		SharedRealmIssuer: cfg.SharedRealmIssuer,
	})
	invalidator := usecase.NewInvalidator(eventCache, realmMap, restricted, appLog)

	// 7. gRPC server (primary inbound adapter): panic-recovery -> request-id
	// -> tracing -> metrics -> logging, from platform-gincommon. Not
	// ProtectedUnaryInterceptors — Envoy calls this service over mTLS, not
	// as a JWT-bearing client, so there's no bearer auth to require here.
	// "mTLS" above describes the intended deployment (a service mesh
	// sidecar or the CNI layer terminating it transparently) — this server
	// listens in plaintext unless GRPC_TLS_CERT_FILE/GRPC_TLS_KEY_FILE are
	// set, for deployments with no such layer.
	serverOpts := []grpc.ServerOption{
		// TimeoutUnaryInterceptor goes innermost (after the observability
		// stack, per gincommon) so metrics/logs/spans record the
		// DeadlineExceeded Envoy receives. It caps a Check that carries no
		// grpc-timeout (or a later one) at GRPC_REQUEST_TIMEOUT; Envoy's own
		// shorter deadline wins when present.
		grpc.ChainUnaryInterceptor(append(grpccommon.ObservabilityUnaryInterceptors(grpcCfg),
			grpccommon.TimeoutUnaryInterceptor(cfg.GRPCRequestTimeout))...),
		grpc.MaxConcurrentStreams(cfg.GRPCMaxConcurrentStreams),
		grpc.MaxRecvMsgSize(cfg.GRPCMaxRecvMsgSizeBytes),
		grpc.MaxSendMsgSize(cfg.GRPCMaxSendMsgSizeBytes),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    cfg.GRPCKeepAliveTime,
			Timeout: cfg.GRPCKeepAliveTimeout,
		}),
	}
	if cfg.GRPCTLSCertFile != "" && cfg.GRPCTLSKeyFile != "" {
		tlsCreds, tlsErr := loadServerTLS(cfg)
		if tlsErr != nil {
			appLog.Error("load grpc tls credentials", map[string]interface{}{"error": tlsErr.Error()})
			return fmt.Errorf("load grpc tls credentials: %w", tlsErr)
		}
		serverOpts = append(serverOpts, grpc.Creds(tlsCreds))
		appLog.Info("grpc server terminating TLS itself", map[string]interface{}{
			"mtls": cfg.GRPCTLSClientCAFile != "",
		})
	}
	grpcServer := grpc.NewServer(serverOpts...)
	authv3.RegisterAuthorizationServer(grpcServer, grpcadapter.NewServer(checker, grpcadapter.JWTMetadata{
		Namespace:  cfg.JWTMetadataNamespace,
		PayloadKey: cfg.JWTPayloadKey,
	}))
	// Native gRPC health checking (grpc.health.v1.Health) — lets Kubernetes'
	// grpc: probe type be used as an alternative to the HTTP /healthz
	// probe below; tied to the same MarkReady() signal, not dependency
	// health (§7 — see ReadinessProbe's doc comment for why).
	healthServer := health.NewServer()
	healthgrpc.RegisterHealthServer(grpcServer, healthServer)
	if cfg.AppEnv != "prod" {
		// Lets grpcurl/grpcui/Postman discover and call Check without a local
		// copy of the envoy ext_authz .proto — same non-production-only
		// convention iam-user-profile uses for its Swagger/AsyncAPI viewers.
		reflection.Register(grpcServer)
	}
	// Limit the grpc_method metric label and server span name to the
	// methods registered above (Check, Health, reflection); anything else
	// (a probe of an unknown service) is recorded as "unknown" instead of
	// minting a new label value per path. Must run after every Register*
	// call and before Serve.
	grpccommon.RegisterKnownMethods(grpcServer)
	var lc net.ListenConfig
	grpcLis, err := lc.Listen(context.Background(), "tcp", ":"+cfg.GRPCPort)
	if err != nil {
		appLog.Error("listen grpc", map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("listen grpc: %w", err)
	}

	// 8. HTTP server (health/readiness, plus the opt-in AsyncAPI viewer —
	// no other business logic).
	probe := &httpadapter.ReadinessProbe{}
	httpServer := &http.Server{
		Addr: ":" + cfg.AppPort,
		Handler: httpadapter.NewRouter(probe, ginCfg, httpadapter.DocsConfig{
			Environment: cfg.AppEnv,
			Enabled:     cfg.DocsEnabled,
			AuthToken:   cfg.DocsAuthToken,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Metrics on a dedicated port/listener, separate from the health/
	// readiness server above — mirrors iam-org-membership's/
	// iam-tender-acl's/iam-user-profile's/iam-catalog-admin's identical
	// split (fleet-wide consistency; this service's AppPort already
	// carries no business API to protect from a shared-port NetworkPolicy
	// grant, since the actual authz decision path is exclusively gRPC).
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", gincommon.MetricsHandler())
	metricsServer := &http.Server{
		Addr:              ":" + cfg.MetricsPort,
		Handler:           metricsMux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// 9. Background workers: the five SQS consumers.
	ctx, cancelBackgroundWork := context.WithCancel(context.Background())
	// fatalErr is the shared "shut down so the orchestrator restarts this
	// pod" signal — not just for consumers. liveness/readiness (values.yaml)
	// are httpGet against the HTTP server, never the gRPC server or its
	// native health service, so an unexpected exit of grpcServer.Serve
	// (or the HTTP/metrics servers) would otherwise go undetected: /healthz
	// keeps reporting healthy while the entire ext_authz decision path — the
	// one thing Envoy actually calls — is silently dead. Buffered so the
	// first fatal source to fire never blocks on a send nobody is receiving
	// yet.
	fatalErr := make(chan error, 1)
	consumers, receiveTrackers, err := startConsumers(ctx, cfg, eventCache, invalidator, appLog, fatalErr)
	if err != nil {
		cancelBackgroundWork()
		appLog.Error("start consumers", map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("start consumers: %w", err)
	}

	// Safety net for fatalErr: platform-events' sqsConsumer.Start() never
	// returns an error for a persistently failing ReceiveMessage loop (IAM
	// permissions revoked, queue deleted, etc.) — it logs and retries
	// forever internally, so fatalErr above would otherwise never fire for
	// that failure mode. Each consumer's SQS client is wrapped to record its
	// own ReceiveMessage outcomes (receive_watchdog.go); the watchdog treats
	// staleAfter consecutive polls with errors and no successful receive as
	// stuck.
	go runReceiveErrorWatchdog(ctx, receiveTrackers, 30*time.Second, 6, fatalErr, appLog)

	// reportFatal is a non-blocking send — fatalErr is 1-buffered and only
	// the first fatal source needs to win; a second concurrent failure
	// during the same shutdown is redundant, not additional information.
	reportFatal := func(err error) {
		select {
		case fatalErr <- err:
		default:
		}
	}

	// 10. Start serving.
	go func() {
		appLog.Info("grpc server listening", map[string]interface{}{"addr": grpcLis.Addr().String()})
		if serveErr := grpcServer.Serve(grpcLis); serveErr != nil {
			appLog.Error("grpc server exited", map[string]interface{}{"error": serveErr.Error()})
			reportFatal(fmt.Errorf("grpc server: %w", serveErr))
		}
	}()
	go func() {
		appLog.Info("http server listening", map[string]interface{}{"addr": httpServer.Addr})
		if serveErr := httpServer.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
			appLog.Error("http server exited", map[string]interface{}{"error": serveErr.Error()})
			reportFatal(fmt.Errorf("http server: %w", serveErr))
		}
	}()
	go func() {
		appLog.Info("metrics server listening", map[string]interface{}{"addr": metricsServer.Addr})
		if serveErr := metricsServer.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
			appLog.Error("metrics server exited", map[string]interface{}{"error": serveErr.Error()})
			reportFatal(fmt.Errorf("metrics server: %w", serveErr))
		}
	}()
	probe.MarkReady()
	healthServer.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)

	// 11. Graceful shutdown, ordered: gRPC -> HTTP -> consumers -> background
	// work cancellation -> cache -> tracing/logging flush.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	// fatalCause is returned after the graceful shutdown below, so main()
	// exits non-zero: a restart caused by a dead server or consumer must show
	// up as a failure (Error/CrashLoopBackOff, restart-count alerts), not as a
	// clean exit 0 ("Completed"). A SIGTERM shutdown still exits 0.
	var fatalCause error
	select {
	case <-quit:
		appLog.Info("shutting down", nil)
	case err := <-fatalErr:
		fatalCause = err
		appLog.Error("fatal error — shutting down so the orchestrator restarts this pod", map[string]interface{}{"error": err.Error()})
	}

	// Reflects the draining state to anything still checking the native
	// gRPC health service before GracefulStop finishes rejecting new RPCs.
	healthServer.SetServingStatus("", healthgrpc.HealthCheckResponse_NOT_SERVING)
	gracefulStopDone := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(gracefulStopDone)
	}()
	select {
	case <-gracefulStopDone:
	case <-time.After(grpcGracefulStopTimeout):
		appLog.Warn("grpc graceful stop timed out — forcing hard stop", map[string]interface{}{
			"timeout": grpcGracefulStopTimeout.String(),
		})
		grpcServer.Stop()
		<-gracefulStopDone // Stop() unblocks the pending GracefulStop() goroutine too.
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer cancelShutdown()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		appLog.Warn("http shutdown error", map[string]interface{}{"error": err.Error()})
	}
	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		appLog.Warn("metrics server shutdown error", map[string]interface{}{"error": err.Error()})
	}

	// Stopped concurrently, not sequentially: each Stop() can take up to its
	// drain timeout plus a margin (platform-events default: 30s + 5s), and
	// five consumers stopped one at a time could push total shutdown time
	// to ~175s in the pathological case of all five genuinely stuck
	// mid-handler at once (e.g. a Valkey outage coinciding with a deploy) —
	// comfortably past most terminationGracePeriodSeconds settings. Running
	// them concurrently bounds worst-case shutdown to one drain window.
	var wg sync.WaitGroup
	for _, c := range consumers {
		wg.Add(1)
		go func(c events.Consumer) {
			defer wg.Done()
			if err := c.Stop(); err != nil {
				appLog.Warn("consumer stop error", map[string]interface{}{"error": err.Error()})
			}
		}(c)
	}
	wg.Wait()
	cancelBackgroundWork()

	if err := eventCache.Close(); err != nil {
		appLog.Warn("event cache close error", map[string]interface{}{"error": err.Error()})
	}
	if err := cache.Close(); err != nil {
		appLog.Warn("cache close error", map[string]interface{}{"error": err.Error()})
	}

	shutdownTracing()
	shutdownErr := grpccommon.Shutdown(appLog)
	if fatalCause != nil {
		return errors.Join(fmt.Errorf("fatal: %w", fatalCause), shutdownErr)
	}
	return shutdownErr
}

// observabilityDomain is this service's business domain in the Platform
// Observability Registry — the domain label on every metric it emits.
const observabilityDomain = "iam"

// initLibraryMetrics registers platform-events' and platform-pgcommon's Tier 1
// platform_* metrics on gincommon's registerer with the identity
// ObservabilityMiddlewares resolved (gincommon.MetricsConstLabels), so all
// three libraries report identical {domain, service, environment} labels.
// MetricsRegisterer — never a LabeledRegisterer wrapper — because both
// libraries inject the identity labels themselves. An invalid identity is an
// error; a metric that cannot be registered is fail-soft and only logged.
func initLibraryMetrics(log usecase.Logger) error {
	labels := gincommon.MetricsConstLabels()
	reg := gincommon.MetricsRegisterer()
	evWarnings, err := events.InitMetrics(events.MetricsIdentityFromLabels(labels), reg)
	if err != nil {
		return fmt.Errorf("platform-events metrics: %w", err)
	}
	for _, w := range evWarnings {
		log.Warn("platform-events metric disabled", map[string]interface{}{"metric": w.Metric, "error": w.Error()})
	}
	pgWarnings, err := pgmetrics.InitWithIdentity(pgmetrics.IdentityFromLabels(labels), reg)
	if err != nil {
		return fmt.Errorf("platform-pgcommon metrics: %w", err)
	}
	for _, w := range pgWarnings {
		log.Warn("platform-pgcommon metric disabled", map[string]interface{}{"metric": w.Metric, "error": w.Error()})
	}
	return nil
}

// loadServerTLS builds the gRPC server's TLS credentials from
// GRPCTLSCertFile/GRPCTLSKeyFile, additionally requiring and verifying a
// client certificate (mTLS) when GRPCTLSClientCAFile is set. Only called
// when both cert and key files are configured — see the call site's
// comment on why this is optional at all.
func loadServerTLS(cfg config.Config) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(cfg.GRPCTLSCertFile, cfg.GRPCTLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if cfg.GRPCTLSClientCAFile != "" {
		caPEM, err := os.ReadFile(cfg.GRPCTLSClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("client CA file %q contains no valid certificates", cfg.GRPCTLSClientCAFile)
		}
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return credentials.NewTLS(tlsConfig), nil
}

// Valkey is the processed_events store (LLD AE-6) behind the same
// IdempotencyStore port iam-org-membership / iam-user-profile use.
var (
	_ consumer.IdempotencyStore = (*valkey.Cache)(nil)
	_ usecase.Cache             = (*valkey.Cache)(nil)
)

// startConsumers builds and starts the five §5 SQS consumers. A consumer
// whose queue URL is unconfigured degrades to a no-op (idle) consumer rather
// than failing startup — useful for partial local-dev setups. Also returns
// a ReceiveMessage tracker per configured (non-idle) queue, by name, for the
// receive-error watchdog.
func startConsumers(ctx context.Context, cfg config.Config, cache *valkey.Cache, inv *usecase.Invalidator, appLog usecase.Logger, fatal chan<- error) ([]events.Consumer, map[string]*receiveTracker, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.AWSRegion))
	if err != nil {
		return nil, nil, fmt.Errorf("load aws config: %w", err)
	}
	sqsClient := sqs.NewFromConfig(awsCfg, func(o *sqs.Options) {
		if cfg.AWSEndpointURL != "" {
			o.BaseEndpoint = &cfg.AWSEndpointURL
		}
	})

	// Shared SQS / SNS / outbox knobs come from platform-events pkg/config
	// — the same LoadSQS / LoadSNS / LoadOutbox + SNSConfigFromEnv /
	// RunnerConfigFromEnv path iam-user-profile / iam-org-membership use.
	// Per-queue URL and concurrency still come from this service's config
	// because there are five queues, not one SQS_QUEUE_URL.
	//
	// Consume-only (HLD §5.4 / EVT-2): assemble the publisher and runner
	// configs so operators get the same SNS_* / OUTBOX_* warnings, then
	// skip NewSNSPublisher, outbox.ApplySchema, and NewRunner. A set
	// DATABASE_URL already warned at PoolConfig above is also named here
	// as an outbox skip so the two composition-root decisions stay next
	// to the helpers that would otherwise start them.
	plat := consumer.LoadPlatform(appLog, cfg.AWSRegion, cfg.AWSEndpointURL)
	if reason := consumer.SNSPublisherSkipReason(plat.SNSTopicARN); reason != "" {
		appLog.Warn(reason, nil)
	}
	if reason := consumer.OutboxRunnerSkipReason(plat.OutboxDatabaseURL); reason != "" {
		appLog.Warn(reason, nil)
	}

	// DLQ forwarding (LLD §16 AE-36): poison messages — a malformed body, a
	// failed Glue decode, a 5th delivery — go to the queue's own
	// RedrivePolicy DLQ instead of being deleted. Built over the plain
	// client, not the watchdog's receive-tracking wrapper. Same publisher
	// iam-org-membership wires.
	dlq, err := consumer.NewDLQPublisher(sqsClient, cfg.AppName, appLog)
	if err != nil {
		return nil, nil, fmt.Errorf("build DLQ publisher: %w", err)
	}

	deps := consumer.Deps{
		Client:      sqsClient,
		SQS:         plat.SQS,
		Cache:       cache,
		Log:         appLog,
		Invalidator: inv,
		DLQ:         dlq,
	}

	builders := []struct {
		name        string
		queueURL    string
		concurrency int
		build       func(string, consumer.Deps, ...events.ConsumerOption) (events.Consumer, error)
	}{
		{"membership-authz-q", cfg.MembershipQueueURL, cfg.MembershipQueueConcurrency, consumer.NewMembershipConsumer},
		{"user-authz-q", cfg.UserQueueURL, cfg.UserQueueConcurrency, consumer.NewUserConsumer},
		{"billing-authz-q", cfg.BillingQueueURL, cfg.BillingQueueConcurrency, consumer.NewBillingConsumer},
		{"tenant-authz-q", cfg.TenantQueueURL, cfg.TenantQueueConcurrency, consumer.NewTenantConsumer},
		{"tender-authz-q", cfg.TenderQueueURL, cfg.TenderQueueConcurrency, consumer.NewTenderConsumer},
	}

	consumers := make([]events.Consumer, 0, len(builders))
	trackers := make(map[string]*receiveTracker, len(builders))
	for _, b := range builders {
		// Each consumer gets its own SQS client wrapper so the watchdog sees
		// that consumer's ReceiveMessage outcomes and nothing else.
		qDeps := deps
		if b.queueURL != "" {
			tr := &receiveTracker{}
			trackers[b.name] = tr
			qDeps.Client = receiveTrackingClient{SQSClientLike: sqsClient, tracker: tr}
		}
		// events.WithConcurrency sets how many messages this consumer hands
		// to handler goroutines at once; the platform-events default is 1
		// (fully serial per queue), which would bottleneck cache-eviction
		// under a burst of events (e.g. a bulk department restructuring).
		c, err := b.build(b.queueURL, qDeps, events.WithConcurrency(b.concurrency))
		if err != nil {
			return nil, nil, fmt.Errorf("build %s consumer: %w", b.name, err)
		}
		consumers = append(consumers, c)
		go func(name string, c events.Consumer) {
			if err := c.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
				appLog.Error("consumer exited", map[string]interface{}{"queue": name, "error": err.Error()})
				select {
				case fatal <- fmt.Errorf("%s: %w", name, err):
				default:
				}
			}
		}(b.name, c)
	}
	return consumers, trackers, nil
}
