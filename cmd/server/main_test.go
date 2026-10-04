package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-gincommon/pkg/gincommon"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/outbound/valkey"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/config"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
)

// writeSelfSignedPair writes a self-signed ECDSA certificate and key (PEM)
// into dir and returns their paths. The certificate is its own CA, so it
// also serves as a client-CA bundle.
func writeSelfSignedPair(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "iam-authz-enrichment"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"iam-authz-enrichment"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

func TestLoadServerTLS(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeSelfSignedPair(t, dir)
	notPEM := filepath.Join(dir, "not-a-ca.pem")
	require.NoError(t, os.WriteFile(notPEM, []byte("not a certificate"), 0o600))

	t.Run("server TLS only", func(t *testing.T) {
		creds, err := loadServerTLS(config.Config{GRPCTLSCertFile: cert, GRPCTLSKeyFile: key})
		require.NoError(t, err)
		assert.Equal(t, "tls", creds.Info().SecurityProtocol)
	})
	t.Run("mTLS with a client CA", func(t *testing.T) {
		creds, err := loadServerTLS(config.Config{GRPCTLSCertFile: cert, GRPCTLSKeyFile: key, GRPCTLSClientCAFile: cert})
		require.NoError(t, err)
		assert.Equal(t, "tls", creds.Info().SecurityProtocol)
	})
	for name, cfg := range map[string]config.Config{
		"missing cert file":       {GRPCTLSCertFile: filepath.Join(dir, "absent.crt"), GRPCTLSKeyFile: key},
		"key does not match cert": {GRPCTLSCertFile: cert, GRPCTLSKeyFile: cert},
		"unreadable client CA":    {GRPCTLSCertFile: cert, GRPCTLSKeyFile: key, GRPCTLSClientCAFile: filepath.Join(dir, "absent-ca.pem")},
		"client CA with no certs": {GRPCTLSCertFile: cert, GRPCTLSKeyFile: key, GRPCTLSClientCAFile: notPEM},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadServerTLS(cfg)
			require.Error(t, err)
		})
	}
}

// recordingLogger keeps Warn calls so a test can assert nothing was disabled.
type recordingLogger struct {
	noopLogger
	warns []string
}

func (l *recordingLogger) Warn(msg string, _ map[string]interface{}) { l.warns = append(l.warns, msg) }

// initLibraryMetrics needs gincommon's identity: before ObservabilityMiddlewares
// it must fail (cmd/server would stop), after it every library metric
// registers. One test function, so the order is guaranteed.
func TestInitLibraryMetrics(t *testing.T) {
	require.Error(t, initLibraryMetrics(noopLogger{}), "no identity yet — the libraries reject an empty domain")

	_ = gincommon.ObservabilityMiddlewares(gincommon.Config{
		ServiceName:  "iam-authz-enrichment",
		BuildVersion: "test",
		Domain:       observabilityDomain,
		Environment:  "test",
	})
	log := &recordingLogger{}
	require.NoError(t, initLibraryMetrics(log))
	assert.Empty(t, log.warns, "no platform-events / platform-pgcommon metric may be disabled")
}

func newTestEventCache(t *testing.T) *valkey.Cache {
	t.Helper()
	c := valkey.New(valkey.Config{Addr: miniredis.RunT(t).Addr(), ReadTimeout: time.Second})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func consumerTestConfig(endpoint string) config.Config {
	return config.Config{
		AppName:                    "iam-authz-enrichment",
		AWSRegion:                  "ap-south-1",
		AWSEndpointURL:             endpoint,
		MembershipQueueConcurrency: 1,
		UserQueueConcurrency:       1,
		BillingQueueConcurrency:    1,
		TenantQueueConcurrency:     1,
		TenderQueueConcurrency:     1,
	}
}

func newTestInvalidator(cache usecase.Cache) *usecase.Invalidator {
	return usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, time.Second), usecase.NewRestrictedTenderSet(time.Second), noopLogger{})
}

// With every queue URL blank (local dev), all five consumers are idle: no
// watchdog trackers, and nothing reaches the fatal channel.
func TestStartConsumers_AllQueuesBlank_IdleConsumers(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	cache := newTestEventCache(t)
	fatal := make(chan error, 1)

	consumers, trackers, err := startConsumers(t.Context(), consumerTestConfig(""), cache, newTestInvalidator(cache), noopLogger{}, fatal)
	require.NoError(t, err)
	assert.Len(t, consumers, 5)
	assert.Empty(t, trackers, "idle consumers are not watched")
	select {
	case err := <-fatal:
		t.Fatalf("idle consumers must not report fatal: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	for _, c := range consumers {
		assert.NoError(t, c.Stop())
	}
}

// A configured queue whose SQS attributes carry no RedrivePolicy is a
// deployment error (LLD §16 AE-36): the consumer refuses to start, and
// startConsumers pushes that onto the fatal channel, so cmd/server shuts
// down and the orchestrator restarts the pod.
func TestStartConsumers_QueueWithoutRedrivePolicy_ReportsFatal(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	sqsFake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		switch target := r.Header.Get("X-Amz-Target"); {
		case strings.HasSuffix(target, "GetQueueAttributes"):
			_, _ = w.Write([]byte(`{"Attributes":{"QueueArn":"arn:aws:sqs:ap-south-1:000000000000:membership-authz-q"}}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(sqsFake.Close)

	cfg := consumerTestConfig(sqsFake.URL)
	cfg.MembershipQueueURL = sqsFake.URL + "/000000000000/membership-authz-q"
	cache := newTestEventCache(t)
	fatal := make(chan error, 1)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	consumers, trackers, err := startConsumers(ctx, cfg, cache, newTestInvalidator(cache), noopLogger{}, fatal)
	require.NoError(t, err)
	assert.Contains(t, trackers, "membership-authz-q", "a configured queue gets a watchdog tracker")
	assert.Len(t, trackers, 1)

	select {
	case err := <-fatal:
		assert.Contains(t, err.Error(), "membership-authz-q")
		assert.Contains(t, err.Error(), "RedrivePolicy")
	case <-time.After(15 * time.Second):
		t.Fatal("a queue without a RedrivePolicy must stop startup via the fatal channel")
	}
	cancel()
	for _, c := range consumers {
		_ = c.Stop()
	}
}
