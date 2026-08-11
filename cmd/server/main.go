// Command server is the iam-authz-enrichment entrypoint: it wires config,
// starts the gRPC ext_authz server, the health/readiness/metrics HTTP
// server, and the five SQS consumers (§1).
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/pkg/events"
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

	// 2. Metrics.
	recorder := metrics.New()

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

	// 4. Org & Membership client.
	orgClient := orgmembership.New(cfg.OrgMembershipBaseURL, cfg.OrgMembershipTimeout)

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
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(grpccommon.ObservabilityUnaryInterceptors(grpccommon.Config{
			ServiceName:  cfg.AppName,
			BuildVersion: buildVersion,
			Logger:       appLog,
		})...),
		grpc.MaxConcurrentStreams(cfg.GRPCMaxConcurrentStreams),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    cfg.GRPCKeepAliveTime,
			Timeout: cfg.GRPCKeepAliveTimeout,
		}),
	)
	authv3.RegisterAuthorizationServer(grpcServer, grpcadapter.NewServer(checker, grpcadapter.JWTMetadata{
		Namespace:  cfg.JWTMetadataNamespace,
		PayloadKey: cfg.JWTPayloadKey,
	}))
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

	// 7. HTTP server (health/readiness/metrics only — no business logic).
	probe := &httpadapter.ReadinessProbe{}
	httpServer := &http.Server{
		Addr:         ":" + cfg.AppPort,
		Handler:      httpadapter.NewRouter(probe),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 8. Background workers: the five SQS consumers.
	ctx, cancelBackgroundWork := context.WithCancel(context.Background())
	consumers, err := startConsumers(ctx, cfg, cache, invalidator, appLog)
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
	probe.MarkReady()

	// 10. Graceful shutdown, ordered: gRPC -> HTTP -> consumers -> background
	// work cancellation -> cache -> tracing/logging flush.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	appLog.Info("shutting down", nil)

	grpcServer.GracefulStop()

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelShutdown()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		appLog.Warn("http shutdown error", map[string]interface{}{"error": err.Error()})
	}

	for _, c := range consumers {
		if err := c.Stop(); err != nil {
			appLog.Warn("consumer stop error", map[string]interface{}{"error": err.Error()})
		}
	}
	cancelBackgroundWork()

	if err := cache.Close(); err != nil {
		appLog.Warn("cache close error", map[string]interface{}{"error": err.Error()})
	}

	return grpccommon.Shutdown(appLog)
}

// startConsumers builds and starts the five §5 SQS consumers. A consumer
// whose queue URL is unconfigured degrades to a no-op (idle) consumer rather
// than failing startup — useful for partial local-dev setups.
func startConsumers(ctx context.Context, cfg config.Config, cache *valkey.Cache, inv *usecase.Invalidator, appLog usecase.Logger) ([]events.Consumer, error) {
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
		Invalidator: inv,
	}

	builders := []struct {
		name     string
		queueURL string
		build    func(string, consumer.Deps, ...events.ConsumerOption) (events.Consumer, error)
	}{
		{"membership-authz-q", cfg.MembershipQueueURL, consumer.NewMembershipConsumer},
		{"user-authz-q", cfg.UserQueueURL, consumer.NewUserConsumer},
		{"billing-authz-q", cfg.BillingQueueURL, consumer.NewBillingConsumer},
		{"tenant-authz-q", cfg.TenantQueueURL, consumer.NewTenantConsumer},
		{"tender-authz-q", cfg.TenderQueueURL, consumer.NewTenderConsumer},
	}

	consumers := make([]events.Consumer, 0, len(builders))
	for _, b := range builders {
		c, err := b.build(b.queueURL, deps)
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
