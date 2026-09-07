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
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	eventsconfig "github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/pkg/config"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/pkg/events"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/gincommon"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/grpccommon"
	gincommonlogger "github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/logger"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/inbound/consumer"
	grpcadapter "github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/inbound/grpc"
	httpadapter "github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/inbound/http"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/outbound/metrics"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/outbound/orgmembership"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/outbound/valkey"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/config"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
)

// buildVersion is overridden at build time via -ldflags (see Dockerfile/Makefile).
var buildVersion = "dev"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Same convention as iam-org-membership/iam-user-profile: Gin defaults
	// to debug mode (verbose per-route registration logging on every
	// startup, plus the framework's own "switch to release mode" warning)
	// unless told otherwise. Without this, every production pod would run
	// debug-mode Gin permanently.
	if cfg.AppEnv != "dev" {
		gin.SetMode(gin.ReleaseMode)
	}

	// 1. Logger — Zap via platform-gincommon (same sink as iam-user-profile
	// / iam-org-membership).
	appLog, err := gincommonlogger.NewLogger(cfg.AppEnv)
	if err != nil {
		return fmt.Errorf("build logger: %w", err)
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

	// Align the env vars platform-gincommon reads directly (InitTracingFromEnv,
	// NewLogger, OTEL_SERVICE_NAME) with this process's identity so a
	// deployment that only set APP_NAME still gets matching trace/metric
	// labels — same ensureGincommonEnv pattern as iam-org-membership /
	// iam-delegation.
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
	// OTEL_EXPORTER_OTLP_ENDPOINT is unset (dev). Interceptor/middleware
	// EnsureInitTelemetry is then a no-op. Flush happens via
	// grpccommon.Shutdown at process exit.
	_ = gincommon.InitTracingFromEnv()

	ginCfg := gincommon.Config{
		Logger:       appLog,
		ServiceName:  cfg.AppName,
		BuildVersion: buildVersion,
	}
	grpcCfg := grpccommon.Config{
		ServiceName:  cfg.AppName,
		BuildVersion: buildVersion,
		Logger:       appLog,
	}

	// ObservabilityMiddlewares is gincommon's public metrics-init API. Call
	// it here (before any collector registration) so authz_* and
	// platform-events metrics land on gincommon.MetricsRegisterer with
	// matching {service, version} const labels — same order as
	// iam-org-membership / iam-user-profile. NewRouter applies the same
	// middleware slice; gincommon's metrics.Init is sync.Once.
	_ = gincommon.ObservabilityMiddlewares(ginCfg)

	// 3. Metrics — business collectors + platform-events consumer
	// collectors, both on gincommon's registerer (the same /metrics scrape
	// as HTTP/gRPC interceptor series).
	recorder := metrics.New(gincommon.MetricsRegisterer())
	events.InitWithRegisterer(cfg.AppName, buildVersion, gincommon.MetricsRegisterer())

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

	// 5. Org & Membership + iam-tender-acl client (I-12/GetTenderACL moved to
	// the latter in ADR-0007 Wave 3 Phase 4 — see orgmembership.New's doc
	// comment).
	orgClient := orgmembership.New(cfg.OrgMembershipBaseURL, cfg.OrgMembershipTimeout, cfg.TenderACLBaseURL, cfg.TenderACLTimeout)

	// 6. In-process policy state + usecase layer.
	realmMap := usecase.NewRealmMap(cfg.RealmTenantMapSeed, cfg.RealmNegativeTTL)
	realmMap.BindStore(cache)
	if err := realmMap.PersistSeed(context.Background()); err != nil {
		appLog.Warn("failed to persist realm-map seed to Valkey — other replicas will not see seed mappings until they load the same env", map[string]interface{}{"error": err.Error()})
	}
	restricted := usecase.NewRestrictedTenderSet(cfg.RestrictedNegativeTTL)
	restricted.BindStore(cache)
	checker := usecase.NewChecker(cache, orgClient, realmMap, restricted, appLog, recorder, usecase.CheckerConfig{
		SharedRealmIssuer: cfg.SharedRealmIssuer,
	})
	invalidator := usecase.NewInvalidator(cache, realmMap, restricted, appLog)

	// 7. gRPC server (primary inbound adapter): panic-recovery -> request-id
	// -> tracing -> metrics -> logging, from platform-gincommon. Not
	// ProtectedUnaryInterceptors — Envoy calls this service over mTLS, not
	// as a JWT-bearing client, so there's no bearer auth to require here.
	// "mTLS" above describes the intended deployment (a service mesh
	// sidecar or the CNI layer terminating it transparently) — this server
	// listens in plaintext unless GRPC_TLS_CERT_FILE/GRPC_TLS_KEY_FILE are
	// set, for deployments with no such layer.
	serverOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(grpccommon.ObservabilityUnaryInterceptors(grpcCfg)...),
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
	if cfg.AppEnv != "production" {
		// Lets grpcurl/grpcui/Postman discover and call Check without a local
		// copy of the envoy ext_authz .proto — same non-production-only
		// convention iam-user-profile uses for its Swagger/AsyncAPI viewers.
		reflection.Register(grpcServer)
	}
	var lc net.ListenConfig
	grpcLis, err := lc.Listen(context.Background(), "tcp", ":"+cfg.GRPCPort)
	if err != nil {
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
	metricsMux.Handle("/metrics", promhttp.Handler())
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
	consumers, queueURLs, err := startConsumers(ctx, cfg, cache, invalidator, appLog, fatalErr)
	if err != nil {
		cancelBackgroundWork()
		return fmt.Errorf("start consumers: %w", err)
	}

	// Safety net for fatalErr: platform-events' sqsConsumer.Start() never
	// returns an error for a persistently failing ReceiveMessage loop (IAM
	// permissions revoked, queue deleted, etc.) — it logs
	// sqs_receive_errors_total and retries forever internally, so fatalErr
	// above would otherwise never fire for that failure mode. This watchdog
	// polls that same counter (platform-events' own "alert when non-zero"
	// metric) and treats staleAfter consecutive polls with no successful
	// receive as stuck.
	go runReceiveErrorWatchdog(ctx, gincommon.MetricsRegisterer(), queueURLs, 30*time.Second, 6, fatalErr, appLog)

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
	select {
	case <-quit:
		appLog.Info("shutting down", nil)
	case err := <-fatalErr:
		appLog.Error("fatal error — shutting down so the orchestrator restarts this pod", map[string]interface{}{"error": err.Error()})
	}

	// Reflects the draining state to anything still checking the native
	// gRPC health service before GracefulStop finishes rejecting new RPCs.
	healthServer.SetServingStatus("", healthgrpc.HealthCheckResponse_NOT_SERVING)
	grpcServer.GracefulStop()

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
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

	if err := cache.Close(); err != nil {
		appLog.Warn("cache close error", map[string]interface{}{"error": err.Error()})
	}

	return grpccommon.Shutdown(appLog)
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
// the configured (non-idle) queues by name, for the receive-error watchdog.
func startConsumers(ctx context.Context, cfg config.Config, cache *valkey.Cache, inv *usecase.Invalidator, appLog usecase.Logger, fatal chan<- error) ([]events.Consumer, map[string]string, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.AWSRegion))
	if err != nil {
		return nil, nil, fmt.Errorf("load aws config: %w", err)
	}
	sqsClient := sqs.NewFromConfig(awsCfg, func(o *sqs.Options) {
		if cfg.AWSEndpointURL != "" {
			o.BaseEndpoint = &cfg.AWSEndpointURL
		}
	})

	// Shared SQS knobs (MaxMessages / WaitSeconds / VisibilityTimeout /
	// Concurrency defaults) come from platform-events pkg/config — the
	// same LoadSQS / SQSConfigFromEnv / SQSConsumerOptions path
	// iam-org-membership uses. Per-queue URL and concurrency still come
	// from this service's config because there are five queues, not one
	// SQS_QUEUE_URL.
	sqsEnv := eventsconfig.LoadSQS()
	eventsconfig.LogWarningsTo(appLog, sqsEnv.Warnings)
	sqsEnv.Region = cfg.AWSRegion
	sqsEnv.EndpointURL = cfg.AWSEndpointURL

	// Outbox is Postgres-backed and only exists for services that publish.
	// This process consumes only (HLD §5.4) — load the env so operators
	// see the same warnings as siblings, then skip the runner.
	outboxEnv := eventsconfig.LoadOutbox()
	eventsconfig.LogWarningsTo(appLog, outboxEnv.Warnings)
	if outboxEnv.DatabaseURL != "" {
		appLog.Warn("DATABASE_URL is set but iam-authz-enrichment publishes no events — platform-events outbox runner not started", nil)
	}

	deps := consumer.Deps{
		Client:      sqsClient,
		SQS:         sqsEnv,
		Cache:       cache,
		Log:         appLog,
		Invalidator: inv,
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
	queueURLs := make(map[string]string, len(builders))
	for _, b := range builders {
		if b.queueURL != "" {
			queueURLs[b.name] = b.queueURL
		}
		// events.WithConcurrency sets how many messages this consumer hands
		// to handler goroutines at once; the platform-events default is 1
		// (fully serial per queue), which would bottleneck cache-eviction
		// under a burst of events (e.g. a bulk department restructuring).
		c, err := b.build(b.queueURL, deps, events.WithConcurrency(b.concurrency))
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
	return consumers, queueURLs, nil
}
