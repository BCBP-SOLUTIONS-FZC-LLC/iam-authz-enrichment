//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fail-fast startup contract: every misconfiguration below must make the real
// binary exit non-zero within seconds, naming the problem — never start and
// then silently fail every request. Each case runs its own short-lived
// instance on ports distinct from the suite's shared server.

// startupEnv is a minimal valid dev environment on spare ports; extra
// overrides it (later entries win in os/exec).
func startupEnv(extra ...string) []string {
	return append(append(os.Environ(),
		"APP_ENV=dev",
		"APP_PORT=18189",
		"GRPC_PORT=19199",
		"METRICS_PORT=19198",
		"VALKEY_URL="+envOr("VALKEY_URL", "localhost:6379"),
		"AWS_REGION="+envOr("AWS_REGION", "ap-south-1"),
		"AWS_ENDPOINT_URL="+endpointURL(),
		"AWS_ACCESS_KEY_ID="+envOr("AWS_ACCESS_KEY_ID", "localstack"),
		"AWS_SECRET_ACCESS_KEY="+envOr("AWS_SECRET_ACCESS_KEY", "localstack"),
		"OTEL_EXPORTER_OTLP_ENDPOINT=none",
		// Blank queues start idle consumers in dev, so only the case under
		// test can stop startup.
		"MEMBERSHIP_AUTHZ_QUEUE_URL=", "USER_AUTHZ_QUEUE_URL=", "BILLING_AUTHZ_QUEUE_URL=",
		"TENANT_AUTHZ_QUEUE_URL=", "TENDER_AUTHZ_QUEUE_URL=",
	), extra...)
}

// runUntilExit starts the binary and waits up to timeout for it to exit,
// returning its combined output. A process still running at the deadline is
// killed and the test fails: the contract is "exit", not "keep serving".
func runUntilExit(t *testing.T, timeout time.Duration, env []string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := exec.CommandContext(context.Background(), e2eBinary)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = &out, &out
	require.NoError(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("binary kept running for %s — expected a fail-fast exit. Output:\n%s", timeout, out.String())
		return "", nil
	}
}

func requireFailFast(t *testing.T, timeout time.Duration, env []string, wantInOutput string) {
	t.Helper()
	out, err := runUntilExit(t, timeout, env)
	var exitErr *exec.ExitError
	require.True(t, errors.As(err, &exitErr), "expected a non-zero exit, got err=%v. Output:\n%s", err, out)
	assert.NotZero(t, exitErr.ExitCode())
	assert.Contains(t, out, wantInOutput)
}

// nonDevBase passes the non-dev checks that run before the sibling-URL and
// queue checks (rediss:// Valkey, a tenant-resolution path), so each staging
// case fails on the one check it names. Load fails before any Valkey dial.
var nonDevBase = []string{
	"APP_ENV=staging",
	"VALKEY_URL=rediss://valkey.example:6379",
	"SHARED_REALM_ISSUER=https://kc.example/realms/shared",
}

func TestStartup_FailsFast(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]struct {
		env  []string
		want string
	}{
		"sibling URL left at its dev default outside dev": {
			env:  append(nonDevBase, "ORG_MEMBERSHIP_BASE_URL="),
			want: "ORG_MEMBERSHIP_BASE_URL is left at its local-dev default",
		},
		"blank queue URL outside dev": {
			env: append(nonDevBase,
				"ORG_MEMBERSHIP_BASE_URL=http://om.example", "TENDER_ACL_BASE_URL=http://tacl.example",
			),
			want: "is required when APP_ENV=",
		},
		"plaintext VALKEY_URL outside dev": {
			env:  []string{"APP_ENV=staging", "VALKEY_URL=localhost:6379"},
			want: "VALKEY_URL must use the rediss:// scheme",
		},
		"no tenant-resolution path outside dev": {
			env:  []string{"APP_ENV=staging", "VALKEY_URL=rediss://valkey.example:6379", "SHARED_REALM_ISSUER=", "REALM_TENANT_MAP_SEED="},
			want: "tenant-resolution",
		},
		"malformed rediss:// VALKEY_URL": {
			env:  []string{"VALKEY_URL=rediss://cache.example:notaport"},
			want: "VALKEY_URL is not a valid",
		},
		"non-positive GRPC_REQUEST_TIMEOUT": {
			env:  []string{"GRPC_REQUEST_TIMEOUT=0s"},
			want: "GRPC_REQUEST_TIMEOUT must be positive",
		},
		"gRPC TLS files that do not exist": {
			env: []string{
				"GRPC_TLS_CERT_FILE=" + filepath.Join(dir, "absent.crt"),
				"GRPC_TLS_KEY_FILE=" + filepath.Join(dir, "absent.key"),
			},
			want: "load grpc tls credentials",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			requireFailFast(t, 15*time.Second, startupEnv(tc.env...), tc.want)
		})
	}
}

// The gRPC port already being bound must stop the process (listen error),
// not leave it serving HTTP health checks with no ext_authz listener.
func TestStartup_GRPCPortInUse_FailsFast(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", ":19199")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	requireFailFast(t, 15*time.Second, startupEnv(), "listen grpc")
}

// LLD §16 AE-36: with DLQ forwarding wired, a configured queue that has no
// RedrivePolicy is a deployment error. The consumer refuses to start and the
// process exits through fatalErr, so the orchestrator restarts the pod
// instead of running with nowhere to send poison messages.
func TestStartup_QueueWithoutRedrivePolicy_ExitsViaFatal(t *testing.T) {
	client := newSQSClient(t)
	name := "e2e-noredrive-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	q, err := client.CreateQueue(context.Background(), &sqs.CreateQueueInput{QueueName: awssdk.String(name)})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = client.DeleteQueue(context.Background(), &sqs.DeleteQueueInput{QueueUrl: q.QueueUrl})
	})

	requireFailFast(t, 30*time.Second, startupEnv("TENDER_AUTHZ_QUEUE_URL="+*q.QueueUrl), "RedrivePolicy")
}

// The counterpart of the fail-fast cases: an orchestrator's SIGTERM is a
// clean, graceful shutdown and must exit 0. (A fatal shutdown — a dead
// server or consumer — exits non-zero; see the RedrivePolicy case above.)
func TestShutdown_SIGTERM_ExitsZero(t *testing.T) {
	var out bytes.Buffer
	cmd := exec.CommandContext(context.Background(), e2eBinary)
	cmd.Env = startupEnv()
	cmd.Stdout, cmd.Stderr = &out, &out
	require.NoError(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	require.Eventually(t, func() bool {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:18189/healthz", nil)
		if err != nil {
			return false
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 15*time.Second, 100*time.Millisecond, "instance never became healthy. Output:\n%s", out.String())

	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
	select {
	case err := <-done:
		require.NoError(t, err, "SIGTERM must exit 0. Output:\n%s", out.String())
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("graceful shutdown exceeded terminationGracePeriodSeconds (60s). Output:\n%s", out.String())
	}
	assert.Contains(t, out.String(), "shutting down")
}
