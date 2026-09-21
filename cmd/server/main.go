// Command server is the iam-authz-enrichment entrypoint: it wires config,
// starts the gRPC ext_authz server, the health/readiness/metrics HTTP
// server, and the five SQS consumers (§1).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

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

	// 1. Logger.
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

	// 2. Metrics. gincommon.MetricsRegisterer() confirms these collectors
	// land on the same registry as platform-gincommon's own HTTP metrics
	// (below) rather than assuming prometheus.DefaultRegisterer and hoping
	// gincommon agrees — same convention as iam-user-profile.
	// Config injects service + environment as ConstLabels on every metric so
	// instrumentation code cannot omit or misspell them (Observability Standard §8).
	recorder := metrics.New(metrics.Config{
		Service:     cfg.AppName,
		Environment: cfg.AppEnv,
	}, gincommon.MetricsRegisterer())

	// 3. Cache.
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

	// 4. Org & Membership + iam-tender-acl client (I-12/GetTenderACL moved to
	// the latter in ADR-0007 Wave 3 Phase 4 — see orgmembership.New's doc
	// comment).
	orgClient := orgmembership.New(cfg.OrgMembershipBaseURL, cfg.OrgMembershipTimeout, cfg.TenderACLBaseURL, cfg.TenderACLTimeout)

	// 5. In-process policy state + usecase layer.
	realmMap := usecase.NewRealmMap(cfg.RealmTenantMapSeed)
	restricted := usecase.NewRestrictedTenderSet()
	checker := usecase.NewChecker(cache, orgClient, realmMap, restricted, appLog, recorder, usecase.CheckerConfig{
		SharedRealmIssuer: cfg.SharedRealmIssuer,
	})
	invalidator := usecase.NewInvalidator(cache, realmMap, restricted, appLog)

	// 6. gRPC server (primary inbound adapter): panic-recovery -> request-id
	// -> tracing -> metrics -> logging, from platform-gincommon. Not
	// ProtectedUnaryInterceptors — Envoy calls this service over mTLS, not
	// as a JWT-bearing client, so there's no bearer auth to require here.
	// "mTLS" above describes the intended deployment (a service mesh
	// sidecar or the CNI layer terminating it transparently) — this server
	// listens in plaintext unless GRPC_TLS_CERT_FILE/GRPC_TLS_KEY_FILE are
	// set, for deployments with no such layer.
	serverOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(grpccommon.ObservabilityUnaryInterceptors(grpccommon.Config{
			ServiceName:  cfg.AppName,
			BuildVersion: buildVersion,
			Logger:       appLog,
		})...),
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

	// 7. HTTP server (health/readiness, plus the opt-in AsyncAPI viewer —
	// no other business logic).
	probe := &httpadapter.ReadinessProbe{}
	httpServer := &http.Server{
		Addr: ":" + cfg.AppPort,
		Handler: httpadapter.NewRouter(probe, gincommon.Config{
			Logger:       appLog,
			ServiceName:  cfg.AppName,
			BuildVersion: buildVersion,
		}, httpadapter.DocsConfig{
			Environment: cfg.AppEnv,
			Enabled:     cfg.DocsEnabled,
			AuthToken:   cfg.DocsAuthToken,
		}),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
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

	// 8. Background workers: the five SQS consumers.
	ctx, cancelBackgroundWork := context.WithCancel(context.Background())
	consumers, err := startConsumers(ctx, cfg, cache, invalidator, appLog, recorder)
	if err != nil {
		cancelBackgroundWork()
		return fmt.Errorf("start consumers: %w", err)
	}

	// 9. Start serving.
	go func() {
		appLog.Info("grpc server listening", map[string]interface{}{"addr": grpcLis.Addr().String()})
		if serveErr := grpcServer.Serve(grpcLis); serveErr != nil {
			appLog.Error("grpc server exited", map[string]interface{}{"error": serveErr.Error()})
		}
	}()
	go func() {
		appLog.Info("http server listening", map[string]interface{}{"addr": httpServer.Addr})
		if serveErr := httpServer.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
			appLog.Error("http server exited", map[string]interface{}{"error": serveErr.Error()})
		}
	}()
	go func() {
		appLog.Info("metrics server listening", map[string]interface{}{"addr": metricsServer.Addr})
		if serveErr := metricsServer.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
			appLog.Error("metrics server exited", map[string]interface{}{"error": serveErr.Error()})
		}
	}()
	probe.MarkReady()
	healthServer.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)

	// 10. Graceful shutdown, ordered: gRPC -> HTTP -> consumers -> background
	// work cancellation -> cache -> tracing/logging flush.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	appLog.Info("shutting down", nil)

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

// startConsumers builds and starts the five §5 SQS consumers. A consumer
// whose queue URL is unconfigured degrades to a no-op (idle) consumer rather
// than failing startup — useful for partial local-dev setups.
func startConsumers(ctx context.Context, cfg config.Config, cache *valkey.Cache, inv *usecase.Invalidator, appLog usecase.Logger, rec *metrics.Recorder) ([]events.Consumer, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.AWSRegion))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	sqsClient := sqs.NewFromConfig(awsCfg, func(o *sqs.Options) {
		if cfg.AWSEndpointURL != "" {
			o.BaseEndpoint = &cfg.AWSEndpointURL
		}
	})

	deps := consumer.Deps{
		Client:      sqsClient,
		Region:      cfg.AWSRegion,
		EndpointURL: cfg.AWSEndpointURL,
		Cache:       cache,
		Log:         appLog,
		Metrics:     rec,
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
	for _, b := range builders {
		// events.WithConcurrency sets how many messages this consumer hands
		// to handler goroutines at once; the platform-events default is 1
		// (fully serial per queue), which would bottleneck cache-eviction
		// under a burst of events (e.g. a bulk department restructuring).
		c, err := b.build(b.queueURL, deps, events.WithConcurrency(b.concurrency))
		if err != nil {
			return nil, fmt.Errorf("build %s consumer: %w", b.name, err)
		}
		consumers = append(consumers, c)
		go func(name string, c events.Consumer) {
			if err := c.Start(ctx); err != nil {
				appLog.Error("consumer exited", map[string]interface{}{"queue": name, "error": err.Error()})
			}
		}(b.name, c)
	}
	return consumers, nil
}
