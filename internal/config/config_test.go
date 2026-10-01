package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/config"
)

// allEnvVars lists every env var config.Load reads — used to reset the
// environment between test cases so no test leaks state into another via a
// var left set by a previous t.Setenv (which testing.T restores after each
// test, but not between subtests sharing a parent unless each gets its own
// t.Setenv call).
var allEnvVars = []string{
	"APP_NAME", "APP_ENV", "APP_PORT", "METRICS_PORT", "GRPC_PORT",
	"VALKEY_URL", "VALKEY_DIAL_TIMEOUT", "VALKEY_READ_TIMEOUT", "VALKEY_WRITE_TIMEOUT",
	"ORG_MEMBERSHIP_BASE_URL", "ORG_MEMBERSHIP_TIMEOUT",
	"TENDER_ACL_BASE_URL", "TENDER_ACL_TIMEOUT",
	"SHARED_REALM_ISSUER", "JWT_METADATA_NAMESPACE", "JWT_PAYLOAD_KEY",
	"AE_CTX_TTL", "AE_CTX_JITTER", "AE_TENDER_ACL_TTL", "AE_NEG_TTL", "AE_RESTRICTED_NEG_TTL", "AE_REALM_NEG_TTL",
	"AE_PROCESSED_EVENT_TTL", "AE_STALE_IF_ERROR_MAX_AGE",
	"GRPC_KEEPALIVE_TIME", "GRPC_KEEPALIVE_TIMEOUT", "GRPC_MAX_CONCURRENT_STREAMS",
	"GRPC_MAX_RECV_MSG_SIZE_BYTES", "GRPC_MAX_SEND_MSG_SIZE_BYTES",
	"GRPC_TLS_CERT_FILE", "GRPC_TLS_KEY_FILE", "GRPC_TLS_CLIENT_CA_FILE",
	"DOCS_ENABLED", "DOCS_AUTH_TOKEN",
	"SQS_MAX_RECEIVE_COUNT",
	"AWS_REGION", "AWS_ENDPOINT_URL",
	"MEMBERSHIP_AUTHZ_QUEUE_URL", "USER_AUTHZ_QUEUE_URL", "BILLING_AUTHZ_QUEUE_URL",
	"TENANT_AUTHZ_QUEUE_URL", "TENDER_AUTHZ_QUEUE_URL",
	"MEMBERSHIP_AUTHZ_QUEUE_CONCURRENCY", "USER_AUTHZ_QUEUE_CONCURRENCY", "BILLING_AUTHZ_QUEUE_CONCURRENCY",
	"TENANT_AUTHZ_QUEUE_CONCURRENCY", "TENDER_AUTHZ_QUEUE_CONCURRENCY",
	"REALM_TENANT_MAP_SEED",
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range allEnvVars {
		t.Setenv(k, "")
	}
}

func TestLoad_Defaults(t *testing.T) {
	clearEnv(t)

	cfg, err := config.Load()

	require.NoError(t, err)
	assert.Equal(t, "iam-authz-enrichment", cfg.AppName)
	assert.Equal(t, "dev", cfg.AppEnv)
	assert.Equal(t, "8080", cfg.AppPort)
	assert.Equal(t, "9090", cfg.MetricsPort)
	assert.Equal(t, "9091", cfg.GRPCPort)
	assert.Equal(t, "localhost:6379", cfg.ValkeyURL)
	assert.Equal(t, 20*time.Millisecond, cfg.ValkeyDialTimeout)
	assert.Equal(t, 10*time.Millisecond, cfg.ValkeyReadTimeout)
	assert.Equal(t, 10*time.Millisecond, cfg.ValkeyWriteTimeout)
	assert.Equal(t, "http://localhost:8081", cfg.OrgMembershipBaseURL)
	assert.Equal(t, 10*time.Millisecond, cfg.OrgMembershipTimeout)
	assert.Equal(t, "http://localhost:8086", cfg.TenderACLBaseURL)
	assert.Equal(t, 20*time.Millisecond, cfg.TenderACLTimeout)
	assert.Equal(t, "", cfg.SharedRealmIssuer)
	assert.Equal(t, "envoy.filters.http.jwt_authn", cfg.JWTMetadataNamespace)
	assert.Equal(t, "trial", cfg.JWTPayloadKey)
	assert.Equal(t, 60*time.Second, cfg.AeCtxTTL)
	assert.Equal(t, 6*time.Second, cfg.AeCtxJitter)
	assert.Equal(t, 15*time.Second, cfg.TenderACLTTL)
	assert.Equal(t, 5*time.Second, cfg.NegativeCacheTTL)
	assert.Equal(t, 5*time.Second, cfg.RestrictedNegativeTTL)
	assert.Equal(t, 5*time.Second, cfg.RealmNegativeTTL)
	assert.Equal(t, 8*24*time.Hour, cfg.ProcessedEventTTL) // PE-1: strictly > 7-day SQS lifetime
	assert.Equal(t, 5*time.Minute, cfg.StaleIfErrorMaxAge)
	assert.Equal(t, 30*time.Second, cfg.GRPCKeepAliveTime)
	assert.Equal(t, 5*time.Second, cfg.GRPCKeepAliveTimeout)
	assert.EqualValues(t, 1000, cfg.GRPCMaxConcurrentStreams)
	assert.Equal(t, 256*1024, cfg.GRPCMaxRecvMsgSizeBytes)
	assert.Equal(t, 256*1024, cfg.GRPCMaxSendMsgSizeBytes)
	assert.Empty(t, cfg.GRPCTLSCertFile)
	assert.Empty(t, cfg.GRPCTLSKeyFile)
	assert.Empty(t, cfg.GRPCTLSClientCAFile)
	assert.False(t, cfg.DocsEnabled)
	assert.Empty(t, cfg.DocsAuthToken)
	assert.Equal(t, "ap-south-1", cfg.AWSRegion)
	assert.Equal(t, "", cfg.AWSEndpointURL)
	assert.Empty(t, cfg.MembershipQueueURL)
	assert.Empty(t, cfg.UserQueueURL)
	assert.Empty(t, cfg.BillingQueueURL)
	assert.Empty(t, cfg.TenantQueueURL)
	assert.Empty(t, cfg.TenderQueueURL)
	assert.Equal(t, 4, cfg.MembershipQueueConcurrency)
	assert.Equal(t, 4, cfg.UserQueueConcurrency)
	assert.Equal(t, 4, cfg.BillingQueueConcurrency)
	assert.Equal(t, 4, cfg.TenantQueueConcurrency)
	assert.Equal(t, 4, cfg.TenderQueueConcurrency)
	assert.NotNil(t, cfg.RealmTenantMapSeed)
	assert.Empty(t, cfg.RealmTenantMapSeed)
}

func TestLoad_CustomValues(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_NAME", "custom-name")
	t.Setenv("APP_ENV", "prod")
	t.Setenv("APP_PORT", "9999")
	t.Setenv("METRICS_PORT", "9997")
	t.Setenv("GRPC_PORT", "9998")
	t.Setenv("VALKEY_URL", "rediss://valkey.internal:6380") // TLS required outside dev
	t.Setenv("VALKEY_DIAL_TIMEOUT", "5ms")
	t.Setenv("VALKEY_READ_TIMEOUT", "6ms")
	t.Setenv("VALKEY_WRITE_TIMEOUT", "7ms")
	t.Setenv("ORG_MEMBERSHIP_BASE_URL", "http://org:8081")
	t.Setenv("ORG_MEMBERSHIP_TIMEOUT", "8ms")
	t.Setenv("TENDER_ACL_BASE_URL", "http://tender-acl:8086")
	t.Setenv("TENDER_ACL_TIMEOUT", "12ms")
	t.Setenv("SHARED_REALM_ISSUER", "https://issuer/shared")
	t.Setenv("JWT_METADATA_NAMESPACE", "custom.namespace")
	t.Setenv("JWT_PAYLOAD_KEY", "custom-key")
	t.Setenv("AE_CTX_TTL", "90s")
	t.Setenv("AE_CTX_JITTER", "9s")
	t.Setenv("AE_TENDER_ACL_TTL", "20s")
	t.Setenv("AE_NEG_TTL", "10s")
	t.Setenv("AE_RESTRICTED_NEG_TTL", "11s")
	t.Setenv("AE_REALM_NEG_TTL", "13s")
	t.Setenv("AE_PROCESSED_EVENT_TTL", "48h")
	t.Setenv("AE_STALE_IF_ERROR_MAX_AGE", "1m")
	t.Setenv("GRPC_KEEPALIVE_TIME", "15s")
	t.Setenv("GRPC_KEEPALIVE_TIMEOUT", "3s")
	t.Setenv("GRPC_MAX_CONCURRENT_STREAMS", "500")
	t.Setenv("GRPC_MAX_RECV_MSG_SIZE_BYTES", "131072")
	t.Setenv("GRPC_MAX_SEND_MSG_SIZE_BYTES", "65536")
	t.Setenv("GRPC_TLS_CERT_FILE", "/tls/tls.crt")
	t.Setenv("GRPC_TLS_KEY_FILE", "/tls/tls.key")
	t.Setenv("GRPC_TLS_CLIENT_CA_FILE", "/tls/ca.crt")
	t.Setenv("DOCS_ENABLED", "true")
	t.Setenv("DOCS_AUTH_TOKEN", "secret-token")
	t.Setenv("SQS_MAX_RECEIVE_COUNT", "3")
	t.Setenv("AWS_REGION", "eu-west-1")
	t.Setenv("AWS_ENDPOINT_URL", "http://localstack:4566")
	t.Setenv("MEMBERSHIP_AUTHZ_QUEUE_URL", "http://q/membership")
	t.Setenv("USER_AUTHZ_QUEUE_URL", "http://q/user")
	t.Setenv("BILLING_AUTHZ_QUEUE_URL", "http://q/billing")
	t.Setenv("TENANT_AUTHZ_QUEUE_URL", "http://q/tenant")
	t.Setenv("TENDER_AUTHZ_QUEUE_URL", "http://q/tender")
	t.Setenv("MEMBERSHIP_AUTHZ_QUEUE_CONCURRENCY", "8")
	t.Setenv("USER_AUTHZ_QUEUE_CONCURRENCY", "6")
	t.Setenv("BILLING_AUTHZ_QUEUE_CONCURRENCY", "2")
	t.Setenv("TENANT_AUTHZ_QUEUE_CONCURRENCY", "2")
	t.Setenv("TENDER_AUTHZ_QUEUE_CONCURRENCY", "3")
	t.Setenv("REALM_TENANT_MAP_SEED", `{"realm-a":"tenant-a"}`)

	cfg, err := config.Load()

	require.NoError(t, err)
	assert.Equal(t, "custom-name", cfg.AppName)
	assert.Equal(t, "prod", cfg.AppEnv)
	assert.Equal(t, "9999", cfg.AppPort)
	assert.Equal(t, "9997", cfg.MetricsPort)
	assert.Equal(t, "9998", cfg.GRPCPort)
	assert.Equal(t, "rediss://valkey.internal:6380", cfg.ValkeyURL)
	assert.Equal(t, 5*time.Millisecond, cfg.ValkeyDialTimeout)
	assert.Equal(t, 6*time.Millisecond, cfg.ValkeyReadTimeout)
	assert.Equal(t, 7*time.Millisecond, cfg.ValkeyWriteTimeout)
	assert.Equal(t, "http://org:8081", cfg.OrgMembershipBaseURL)
	assert.Equal(t, 8*time.Millisecond, cfg.OrgMembershipTimeout)
	assert.Equal(t, "http://tender-acl:8086", cfg.TenderACLBaseURL)
	assert.Equal(t, 12*time.Millisecond, cfg.TenderACLTimeout)
	assert.Equal(t, "https://issuer/shared", cfg.SharedRealmIssuer)
	assert.Equal(t, "custom.namespace", cfg.JWTMetadataNamespace)
	assert.Equal(t, "custom-key", cfg.JWTPayloadKey)
	assert.Equal(t, 90*time.Second, cfg.AeCtxTTL)
	assert.Equal(t, 9*time.Second, cfg.AeCtxJitter)
	assert.Equal(t, 20*time.Second, cfg.TenderACLTTL)
	assert.Equal(t, 10*time.Second, cfg.NegativeCacheTTL)
	assert.Equal(t, 11*time.Second, cfg.RestrictedNegativeTTL)
	assert.Equal(t, 13*time.Second, cfg.RealmNegativeTTL)
	assert.Equal(t, 48*time.Hour, cfg.ProcessedEventTTL)
	assert.Equal(t, time.Minute, cfg.StaleIfErrorMaxAge)
	assert.Equal(t, 15*time.Second, cfg.GRPCKeepAliveTime)
	assert.Equal(t, 3*time.Second, cfg.GRPCKeepAliveTimeout)
	assert.EqualValues(t, 500, cfg.GRPCMaxConcurrentStreams)
	assert.Equal(t, 131072, cfg.GRPCMaxRecvMsgSizeBytes)
	assert.Equal(t, 65536, cfg.GRPCMaxSendMsgSizeBytes)
	assert.Equal(t, "/tls/tls.crt", cfg.GRPCTLSCertFile)
	assert.Equal(t, "/tls/tls.key", cfg.GRPCTLSKeyFile)
	assert.Equal(t, "/tls/ca.crt", cfg.GRPCTLSClientCAFile)
	assert.True(t, cfg.DocsEnabled)
	assert.Equal(t, "secret-token", cfg.DocsAuthToken)
	assert.Equal(t, "eu-west-1", cfg.AWSRegion)
	assert.Equal(t, "http://localstack:4566", cfg.AWSEndpointURL)
	assert.Equal(t, "http://q/membership", cfg.MembershipQueueURL)
	assert.Equal(t, "http://q/user", cfg.UserQueueURL)
	assert.Equal(t, "http://q/billing", cfg.BillingQueueURL)
	assert.Equal(t, "http://q/tenant", cfg.TenantQueueURL)
	assert.Equal(t, "http://q/tender", cfg.TenderQueueURL)
	assert.Equal(t, 8, cfg.MembershipQueueConcurrency)
	assert.Equal(t, 6, cfg.UserQueueConcurrency)
	assert.Equal(t, 2, cfg.BillingQueueConcurrency)
	assert.Equal(t, 2, cfg.TenantQueueConcurrency)
	assert.Equal(t, 3, cfg.TenderQueueConcurrency)
	assert.Equal(t, map[string]string{"realm-a": "tenant-a"}, cfg.RealmTenantMapSeed)
}

// TestLoad_StaleIfErrorMaxAge_ClampedToHardCap proves the §7 hard cap is
// enforced regardless of what a misconfigured env var requests.
func TestLoad_StaleIfErrorMaxAge_ClampedToHardCap(t *testing.T) {
	clearEnv(t)
	t.Setenv("AE_STALE_IF_ERROR_MAX_AGE", "1h")

	cfg, err := config.Load()

	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, cfg.StaleIfErrorMaxAge, "must never exceed the hard cap even if configured higher")
}

func TestLoad_StaleIfErrorMaxAge_BelowCapPassesThrough(t *testing.T) {
	clearEnv(t)
	t.Setenv("AE_STALE_IF_ERROR_MAX_AGE", "30s")

	cfg, err := config.Load()

	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, cfg.StaleIfErrorMaxAge)
}

// TestLoad_InvalidDuration_EachField exercises every envDuration-backed
// field's error-return branch individually.
func TestLoad_InvalidDuration_EachField(t *testing.T) {
	fields := []string{
		"VALKEY_DIAL_TIMEOUT", "VALKEY_READ_TIMEOUT", "VALKEY_WRITE_TIMEOUT",
		"ORG_MEMBERSHIP_TIMEOUT", "TENDER_ACL_TIMEOUT", "AE_CTX_TTL", "AE_CTX_JITTER", "AE_TENDER_ACL_TTL",
		"AE_NEG_TTL", "AE_RESTRICTED_NEG_TTL", "AE_REALM_NEG_TTL", "AE_PROCESSED_EVENT_TTL", "AE_STALE_IF_ERROR_MAX_AGE",
		"GRPC_KEEPALIVE_TIME", "GRPC_KEEPALIVE_TIMEOUT",
	}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			clearEnv(t)
			t.Setenv(field, "not-a-duration")

			_, err := config.Load()

			require.Error(t, err)
			assert.Contains(t, err.Error(), field)
		})
	}
}

// TestLoad_InvalidInt_EachField exercises every envInt-backed field's
// error-return branch individually.
func TestLoad_InvalidInt_EachField(t *testing.T) {
	fields := []string{
		"GRPC_MAX_CONCURRENT_STREAMS",
		"GRPC_MAX_RECV_MSG_SIZE_BYTES", "GRPC_MAX_SEND_MSG_SIZE_BYTES",
		"MEMBERSHIP_AUTHZ_QUEUE_CONCURRENCY", "USER_AUTHZ_QUEUE_CONCURRENCY", "BILLING_AUTHZ_QUEUE_CONCURRENCY",
		"TENANT_AUTHZ_QUEUE_CONCURRENCY", "TENDER_AUTHZ_QUEUE_CONCURRENCY",
	}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			clearEnv(t)
			t.Setenv(field, "not-an-int")

			_, err := config.Load()

			require.Error(t, err)
			assert.Contains(t, err.Error(), field)
		})
	}
}

// TestLoad_NonPositiveInt_EachField exercises envPositiveInt's fail-fast
// range check — a zero or negative value for one of these fields would
// otherwise silently misbehave at runtime instead of failing at startup
// (a gRPC server with zero concurrent streams allowed, a consumer built
// with negative concurrency, a message-size cap that permits nothing).
func TestLoad_NonPositiveInt_EachField(t *testing.T) {
	fields := []string{
		"GRPC_MAX_CONCURRENT_STREAMS",
		"GRPC_MAX_RECV_MSG_SIZE_BYTES", "GRPC_MAX_SEND_MSG_SIZE_BYTES",
		"MEMBERSHIP_AUTHZ_QUEUE_CONCURRENCY", "USER_AUTHZ_QUEUE_CONCURRENCY", "BILLING_AUTHZ_QUEUE_CONCURRENCY",
		"TENANT_AUTHZ_QUEUE_CONCURRENCY", "TENDER_AUTHZ_QUEUE_CONCURRENCY",
	}
	for _, field := range fields {
		for _, bad := range []string{"0", "-1"} {
			t.Run(field+"/"+bad, func(t *testing.T) {
				clearEnv(t)
				t.Setenv(field, bad)

				_, err := config.Load()

				require.Error(t, err)
				assert.Contains(t, err.Error(), field)
				assert.Contains(t, err.Error(), "positive")
			})
		}
	}
}

// TestLoad_GRPCMaxConcurrentStreams_ExceedsUint32Range proves a value that
// would silently wrap via the uint32(streams) narrowing conversion instead
// fails fast at startup.
func TestLoad_GRPCMaxConcurrentStreams_ExceedsUint32Range(t *testing.T) {
	clearEnv(t)
	t.Setenv("GRPC_MAX_CONCURRENT_STREAMS", "4294967296") // math.MaxUint32 + 1

	_, err := config.Load()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "GRPC_MAX_CONCURRENT_STREAMS")
	assert.Contains(t, err.Error(), "exceeds")
}

func TestLoad_InvalidBool_EachField(t *testing.T) {
	fields := []string{"DOCS_ENABLED"}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			clearEnv(t)
			t.Setenv(field, "not-a-bool")

			_, err := config.Load()

			require.Error(t, err)
			assert.Contains(t, err.Error(), field)
		})
	}
}

func TestLoad_InvalidRealmTenantMapSeed_JSON(t *testing.T) {
	clearEnv(t)
	t.Setenv("REALM_TENANT_MAP_SEED", "not-json")

	_, err := config.Load()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "REALM_TENANT_MAP_SEED")
}

// TestLoad_OrgMembershipDevDefault_FailsOutsideDev proves a deployment left
// pointed at the local-dev Org & Membership URL fails fast at startup
// instead of starting, passing health checks, and silently failing every
// request that isn't a cache hit.
func TestLoad_OrgMembershipDevDefault_FailsOutsideDev(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("VALKEY_URL", "rediss://valkey.iam.svc.cluster.local:6379")
	t.Setenv("SHARED_REALM_ISSUER", "https://keycloak.example.com/realms/shared") // avoid earlier check
	// ORG_MEMBERSHIP_BASE_URL left unset — resolves to the dev default.

	_, err := config.Load()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "ORG_MEMBERSHIP_BASE_URL")
}

// TestLoad_OrgMembershipDevDefault_AllowedInDev proves the same default is
// fine when APP_ENV is (or defaults to) dev — this is the normal local
// developer setup, not a misconfiguration.
func TestLoad_OrgMembershipDevDefault_AllowedInDev(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "dev")

	cfg, err := config.Load()

	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8081", cfg.OrgMembershipBaseURL)
}

// TestLoad_OrgMembershipOverridden_PassesOutsideDev proves the check is on
// the *value*, not the environment alone — a properly configured production
// deployment must not be blocked by this validation.
func TestLoad_OrgMembershipOverridden_PassesOutsideDev(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "production")
	setRequiredProductionEnv(t)
	t.Setenv("ORG_MEMBERSHIP_BASE_URL", "http://org-membership.iam.svc.cluster.local:8080")
	t.Setenv("TENDER_ACL_BASE_URL", "http://tender-acl.iam.svc.cluster.local:8080")

	cfg, err := config.Load()

	require.NoError(t, err)
	assert.Equal(t, "http://org-membership.iam.svc.cluster.local:8080", cfg.OrgMembershipBaseURL)
	assert.Equal(t, "http://tender-acl.iam.svc.cluster.local:8080", cfg.TenderACLBaseURL)
}

func setRequiredQueueURLs(t *testing.T) {
	t.Helper()
	t.Setenv("MEMBERSHIP_AUTHZ_QUEUE_URL", "http://q/membership")
	t.Setenv("USER_AUTHZ_QUEUE_URL", "http://q/user")
	t.Setenv("BILLING_AUTHZ_QUEUE_URL", "http://q/billing")
	t.Setenv("TENANT_AUTHZ_QUEUE_URL", "http://q/tenant")
	t.Setenv("TENDER_AUTHZ_QUEUE_URL", "http://q/tender")
}

// setRequiredProductionEnv sets all env vars that Load() requires outside
// APP_ENV=dev so individual non-dev tests can focus on the one var under test
// without being blocked by unrelated checks.
func setRequiredProductionEnv(t *testing.T) {
	t.Helper()
	t.Setenv("VALKEY_URL", "rediss://valkey.iam.svc.cluster.local:6379")
	t.Setenv("ORG_MEMBERSHIP_BASE_URL", "http://org-membership.iam.svc.cluster.local:8080")
	t.Setenv("TENDER_ACL_BASE_URL", "http://tender-acl.iam.svc.cluster.local:8086")
	t.Setenv("SHARED_REALM_ISSUER", "https://keycloak.example.com/realms/shared")
	setRequiredQueueURLs(t)
}

func TestLoad_QueueURLRequiredOutsideDev(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "production")
	setRequiredProductionEnv(t)
	// Override TENDER_AUTHZ_QUEUE_URL to blank to test the missing-queue check.
	t.Setenv("TENDER_AUTHZ_QUEUE_URL", "")

	_, err := config.Load()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "TENDER_AUTHZ_QUEUE_URL")
}

func TestLoad_QueueURLBlankAllowedInDev(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "dev")

	cfg, err := config.Load()

	require.NoError(t, err)
	assert.Empty(t, cfg.TenderQueueURL)
}

func TestLoad_DuplicateQueueURL_Fails(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "dev")
	t.Setenv("MEMBERSHIP_AUTHZ_QUEUE_URL", "http://q/shared")
	t.Setenv("USER_AUTHZ_QUEUE_URL", "http://q/shared")

	_, err := config.Load()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "MEMBERSHIP_AUTHZ_QUEUE_URL")
	assert.Contains(t, err.Error(), "USER_AUTHZ_QUEUE_URL")
}

func TestLoad_DuplicateQueueURL_BlanksExempt(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "dev")
	// Both left blank — must not be treated as a "duplicate" of each other.

	_, err := config.Load()

	require.NoError(t, err)
}

// TestLoad_TenderACLDevDefault_FailsOutsideDev / _AllowedInDev /
// TestLoad_TenderACLOverridden_PassesOutsideDev mirror the three
// OrgMembership tests above, for TENDER_ACL_BASE_URL (ADR-0007 Wave 3
// Phase 4).

func TestLoad_TenderACLDevDefault_FailsOutsideDev(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("VALKEY_URL", "rediss://valkey.iam.svc.cluster.local:6379")
	t.Setenv("SHARED_REALM_ISSUER", "https://keycloak.example.com/realms/shared") // avoid earlier check
	// ORG_MEMBERSHIP_BASE_URL must be overridden too, or that check fires
	// first and this test would be asserting the wrong error message.
	t.Setenv("ORG_MEMBERSHIP_BASE_URL", "http://org-membership.iam.svc.cluster.local:8080")
	// TENDER_ACL_BASE_URL left unset — resolves to the dev default.

	_, err := config.Load()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "TENDER_ACL_BASE_URL")
}

func TestLoad_TenderACLDevDefault_AllowedInDev(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "dev")

	cfg, err := config.Load()

	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8086", cfg.TenderACLBaseURL)
}

// TestLoad_ValkeyTLS_* prove the rediss:// enforcement invariant: plaintext
// Valkey must be rejected outside dev (authorization context is sensitive),
// and rediss:// must be accepted. Dev is exempt (no TLS in local docker-compose).

func TestLoad_ValkeyTLS_PlaintextFailsOutsideDev(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("VALKEY_URL", "localhost:6379") // plain host:port — no TLS

	_, err := config.Load()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "VALKEY_URL")
	assert.Contains(t, err.Error(), "rediss://")
}

func TestLoad_ValkeyTLS_RedisSchemeFailsOutsideDev(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("VALKEY_URL", "redis://valkey:6379") // redis:// is plaintext

	_, err := config.Load()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "rediss://")
}

func TestLoad_ValkeyTLS_RedissPassesOutsideDev(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "production")
	setRequiredProductionEnv(t) // sets rediss:// Valkey URL + other required vars

	cfg, err := config.Load()

	require.NoError(t, err)
	assert.True(t, len(cfg.ValkeyURL) > 0)
}

func TestLoad_ValkeyTLS_PlaintextAllowedInDev(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "dev")
	t.Setenv("VALKEY_URL", "localhost:6379") // plain — fine in dev

	cfg, err := config.Load()

	require.NoError(t, err)
	assert.Equal(t, "localhost:6379", cfg.ValkeyURL)
}

// TestLoad_SharedRealmIssuer_* prove the fail-fast invariant: both
// SHARED_REALM_ISSUER and REALM_TENANT_MAP_SEED empty outside dev means no
// tenant-resolution path exists, so Load() must fail rather than starting a
// process that silently returns DENY_MALFORMED_IDENTITY on every request.

func TestLoad_SharedRealmIssuerBothEmpty_FailsOutsideDev(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("VALKEY_URL", "rediss://valkey.iam.svc.cluster.local:6379")
	t.Setenv("ORG_MEMBERSHIP_BASE_URL", "http://org-membership.iam.svc.cluster.local:8080")
	t.Setenv("TENDER_ACL_BASE_URL", "http://tender-acl.iam.svc.cluster.local:8086")
	setRequiredQueueURLs(t)
	// SHARED_REALM_ISSUER left blank (default). REALM_TENANT_MAP_SEED left as "{}" (empty map).

	_, err := config.Load()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant-resolution")
}

func TestLoad_SharedRealmIssuerBothEmpty_AllowedInDev(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "dev")
	// Both empty — fine in dev.

	cfg, err := config.Load()

	require.NoError(t, err)
	assert.Empty(t, cfg.SharedRealmIssuer)
	assert.Empty(t, cfg.RealmTenantMapSeed)
}

func TestLoad_SharedRealmIssuerSet_PassesOutsideDev(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "production")
	setRequiredProductionEnv(t) // includes SHARED_REALM_ISSUER

	cfg, err := config.Load()

	require.NoError(t, err)
	assert.NotEmpty(t, cfg.SharedRealmIssuer)
}

func TestLoad_RealmMapSeedSet_PassesOutsideDev(t *testing.T) {
	clearEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("VALKEY_URL", "rediss://valkey.iam.svc.cluster.local:6379")
	t.Setenv("ORG_MEMBERSHIP_BASE_URL", "http://org-membership.iam.svc.cluster.local:8080")
	t.Setenv("TENDER_ACL_BASE_URL", "http://tender-acl.iam.svc.cluster.local:8086")
	t.Setenv("REALM_TENANT_MAP_SEED", `{"kc.example.com/realms/tenant-a": "tenant-uuid-a"}`)
	// SHARED_REALM_ISSUER left blank — seed alone should be enough.
	setRequiredQueueURLs(t)

	cfg, err := config.Load()

	require.NoError(t, err)
	assert.Len(t, cfg.RealmTenantMapSeed, 1)
}
