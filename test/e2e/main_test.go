//go:build e2e

// Package e2e drives the real, compiled iam-authz-enrichment binary over
// the network — the one test tier that exercises the full stack Envoy
// actually depends on (the gRPC server, real Valkey, the real SQS
// consumers, and the real Org & Membership/Tender ACL HTTP client) rather
// than a single adapter in isolation via a fake. Unit tests
// (internal/.../*_test.go) and test/integration already cover every branch
// of the precedence chain and every adapter individually with 100%
// coverage; this tier exists to catch wiring/config regressions those two
// tiers structurally cannot see — an env var renamed in config.go but not
// propagated to the Helm chart, a context_extensions key that stops
// round-tripping through the real wire format, a startup ordering bug that
// only shows up when every real dependency is actually reachable at once.
//
// This automates the exact manual walkthrough README.md's "Exercising the
// gRPC API locally" / "Testing events locally" sections describe by hand
// with grpcurl + docker compose exec — see those sections for the
// equivalent commands if you want to reproduce a failure interactively.
//
// Requires (see Makefile's test-e2e target):
//   - a real Valkey reachable at VALKEY_URL (default localhost:6379)
//   - a real SQS-compatible emulator reachable at AWS_ENDPOINT_URL (default
//     http://localhost:4566 — floci locally via `make docker-up`, LocalStack
//     in CI) with the five queues already provisioned (scripts/init-floci.sh
//     / scripts/init-localstack.sh)
//   - the compiled binary at E2E_BINARY_PATH (default
//     ../../bin/iam-authz-enrichment) — run `make build` first
package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Fixed, distinctive high ports for the one e2e server instance this
// package starts — no collision risk with docker-compose.yml's own
// app/valkey/floci port mappings (8080/9090/9091 and friends), which this
// process runs alongside, not instead of.
const (
	e2eAppPort     = "18089"
	e2eGRPCPort    = "19099"
	e2eMetricsPort = "19098"

	e2eTestIssuer = "https://kc.example.com/realms/e2e-shared-trial"
)

var (
	org        *fakeOrg
	grpcClient authv3.AuthorizationClient

	// runID scopes every tenant/user/tender ID this suite constructs (see
	// id() below) to one test invocation. Several facts this service caches
	// have no TTL by design (ae:restricted — TenderRestricted is monotonic,
	// AE-23/§8.5.1) and this suite runs against a real, persistent Valkey,
	// not a fresh one per run — without this, a tender flagged restricted
	// by one `go test -tags=e2e` invocation would still read as restricted
	// on the next one, silently corrupting that run's "not yet restricted"
	// sanity check.
	runID string
)

// id suffixes base with the current run's unique ID, so two separate
// invocations of this suite against the same Valkey/floci instance never
// share a cache key.
func id(base string) string { return base + "-" + runID }

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	runID = uuid.NewString()[:8]

	binaryPath := envOr("E2E_BINARY_PATH", "../../bin/iam-authz-enrichment")
	if _, err := os.Stat(binaryPath); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: binary not found at %s — run `make build` first (or set E2E_BINARY_PATH)\n", binaryPath)
		return 1
	}

	org = newFakeOrg()
	defer org.Close()

	var logs bytes.Buffer
	// CommandContext with Background(), not the plain Command constructor:
	// this process's own lifecycle (stopServer's SIGTERM-then-Kill below) is
	// what actually bounds the subprocess, not a context deadline — using
	// CommandContext here is just satisfying the same "always thread a
	// context through exec.Command" convention the rest of this codebase's
	// linting expects, not adding real cancellation behavior.
	cmd := exec.CommandContext(context.Background(), binaryPath)
	cmd.Env = append(os.Environ(),
		"APP_ENV=dev",
		"APP_PORT="+e2eAppPort,
		"GRPC_PORT="+e2eGRPCPort,
		"METRICS_PORT="+e2eMetricsPort,
		"VALKEY_URL="+envOr("VALKEY_URL", "localhost:6379"),
		"AWS_REGION="+envOr("AWS_REGION", "ap-south-1"),
		"AWS_ENDPOINT_URL="+endpointURL(),
		"AWS_ACCESS_KEY_ID="+envOr("AWS_ACCESS_KEY_ID", "localstack"),
		"AWS_SECRET_ACCESS_KEY="+envOr("AWS_SECRET_ACCESS_KEY", "localstack"),
		"MEMBERSHIP_AUTHZ_QUEUE_URL="+queueURLEnv("membership-authz-q"),
		"USER_AUTHZ_QUEUE_URL="+queueURLEnv("user-authz-q"),
		"BILLING_AUTHZ_QUEUE_URL="+queueURLEnv("billing-authz-q"),
		"TENANT_AUTHZ_QUEUE_URL="+queueURLEnv("tenant-authz-q"),
		"TENDER_AUTHZ_QUEUE_URL="+queueURLEnv("tender-authz-q"),
		"ORG_MEMBERSHIP_BASE_URL="+org.URL(),
		"TENDER_ACL_BASE_URL="+org.URL(),
		"ORG_MEMBERSHIP_TIMEOUT=2s",
		"TENDER_ACL_TIMEOUT=2s",
		"SHARED_REALM_ISSUER="+e2eTestIssuer,
		"DOCS_ENABLED=false",
	)
	cmd.Stdout = &logs
	cmd.Stderr = &logs

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: failed to start server: %v\n", err)
		return 1
	}
	defer stopServer(cmd)

	if err := waitForHealthy(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: server never became healthy: %v\nserver output:\n%s\n", err, logs.String())
		return 1
	}

	conn, err := grpc.NewClient("127.0.0.1:"+e2eGRPCPort, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: failed to dial grpc server: %v\n", err)
		return 1
	}
	defer func() { _ = conn.Close() }()
	grpcClient = authv3.NewAuthorizationClient(conn)

	code := m.Run()
	if code != 0 {
		fmt.Fprintf(os.Stderr, "e2e: server output on failure:\n%s\n", logs.String())
	}
	return code
}

// stopServer sends SIGTERM (the same signal Kubernetes sends, exercising
// the real graceful-shutdown path — cmd/server/main.go's grpcServer.
// GracefulStop/httpShutdownTimeout/consumer-drain sequence) and falls back
// to a hard Kill if it doesn't exit in time, so a shutdown regression fails
// this test loudly instead of hanging the whole suite.
func stopServer(cmd *exec.Cmd) {
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}

func waitForHealthy() error {
	deadline := time.Now().Add(20 * time.Second)
	url := "http://127.0.0.1:" + e2eAppPort + "/healthz"
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:gosec,noctx // fixed localhost test URL, no request context needed for a short-lived poll
		if err != nil {
			lastErr = err
		} else {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return lastErr
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func endpointURL() string {
	return envOr("AWS_ENDPOINT_URL", "http://localhost:4566")
}

func queueURLEnv(name string) string {
	return endpointURL() + "/000000000000/" + name
}

func checkContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// eventually retries cond until it returns true or timeout elapses, failing
// the test otherwise — used for the event-driven scenarios (cache eviction,
// tender-restriction) where the SQS consumer's long-poll delivery isn't
// instantaneous, so asserting on a single Check() call right after
// send-message would be flaky by construction.
func eventually(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("condition not met within %s", timeout)
	}
}
