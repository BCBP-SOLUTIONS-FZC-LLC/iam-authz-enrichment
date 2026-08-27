// Package config loads runtime configuration from environment variables.
// No database-backed config (this service has no database) and no
// hot-reload — a TTL or timeout change requires a config change and rolling
// restart (§11).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config is the fully-resolved runtime configuration.
type Config struct {
	AppName     string
	AppEnv      string
	AppPort     string
	MetricsPort string
	GRPCPort    string

	ValkeyURL          string
	ValkeyDialTimeout  time.Duration
	ValkeyReadTimeout  time.Duration
	ValkeyWriteTimeout time.Duration

	OrgMembershipBaseURL string
	OrgMembershipTimeout time.Duration

	// TenderACLBaseURL/TenderACLTimeout back I-12 (GetTenderACL) only, since
	// ADR-0007 Wave 3 Phase 4 repoints that one call at iam-tender-acl —
	// I-8/I-14 stay on OrgMembershipBaseURL above. A separate, tighter
	// timeout than OrgMembershipTimeout's 10ms default: iam-tender-acl's own
	// TAC-4 SLO is 5ms cache-hit/20ms cache-miss (its LLD §14.1), and this
	// client has no visibility into which case a given call will hit.
	TenderACLBaseURL string
	TenderACLTimeout time.Duration

	// SharedRealmIssuer is the Keycloak issuer URL for the shared trial
	// realm — the fallback tenant-resolution path for tenants not yet in
	// the dedicated realm→tenant map (§2 point 3).
	SharedRealmIssuer string
	// JWTMetadataNamespace/JWTPayloadKey locate the Envoy jwt_authn filter's
	// verified-claims dynamic metadata on the inbound CheckRequest — see
	// internal/adapter/inbound/grpc/claims.go.
	JWTMetadataNamespace string
	JWTPayloadKey        string

	// AeCtxTTL/AeCtxJitter implement the §4.1 "60s ± 6s jitter" key schedule.
	AeCtxTTL           time.Duration
	AeCtxJitter        time.Duration
	TenderACLTTL       time.Duration
	NegativeCacheTTL   time.Duration
	ProcessedEventTTL  time.Duration
	StaleIfErrorMaxAge time.Duration

	GRPCMaxConcurrentStreams uint32
	GRPCKeepAliveTime        time.Duration
	GRPCKeepAliveTimeout     time.Duration
	GRPCMaxRecvMsgSizeBytes  int
	GRPCMaxSendMsgSizeBytes  int

	// GRPCTLSCertFile/GRPCTLSKeyFile: when both are set, the gRPC server
	// terminates TLS itself instead of listening in plaintext. Optional —
	// most deployments terminate mTLS at a service mesh sidecar or the CNI
	// layer instead (see README § Security), but the app-level option must
	// exist for environments without one. GRPCTLSClientCAFile additionally
	// requires and verifies a client certificate (mTLS) when set; leave it
	// empty for server-side-only TLS.
	GRPCTLSCertFile     string
	GRPCTLSKeyFile      string
	GRPCTLSClientCAFile string

	// DocsEnabled/DocsAuthToken gate the AsyncAPI event-contract viewer
	// (/asyncapi, /asyncapi.yaml — internal/adapter/inbound/http's
	// DocsConfig). Outside AppEnv=="production" the viewer is always on
	// regardless of DocsEnabled; in production it's opt-in via DocsEnabled
	// and, if DocsAuthToken is set, gated behind a bearer token.
	DocsEnabled   bool
	DocsAuthToken string

	AWSRegion      string
	AWSEndpointURL string // LocalStack endpoint override; empty in real AWS

	MembershipQueueURL string
	UserQueueURL       string
	BillingQueueURL    string
	TenantQueueURL     string
	TenderQueueURL     string
	SQSMaxReceiveCount int

	// *QueueConcurrency sets events.WithConcurrency per queue — the number
	// of messages each consumer hands to a handler goroutine at once,
	// rather than the platform-events library default of 1 (fully serial
	// per queue). Same per-queue-configurable pattern as
	// iam-org-membership's SQS_*_CONCURRENCY vars.
	MembershipQueueConcurrency int
	UserQueueConcurrency       int
	BillingQueueConcurrency    int
	TenantQueueConcurrency     int
	TenderQueueConcurrency     int

	// RealmTenantMapSeed is the startup seed for the in-process realm→tenant
	// map (JSON object, realm -> tenant_id). Events (TenantConverted,
	// TenantRealmReady) update the map at runtime from their payload (§5) —
	// this seed only covers what's active at process start, since this
	// service is stateless and rebuilds no state from a database on boot.
	RealmTenantMapSeed map[string]string
}

// stateless-if-error hard cap (§7): "5 additional minutes... hard cap...
// don't extend it further without checking". Enforced regardless of what a
// misconfigured env var requests.
const staleIfErrorHardCap = 5 * time.Minute

// devOrgMembershipBaseURL is the local-dev default — never a valid address
// for a real Org & Membership service, so Load() fails outside APP_ENV=dev
// if this is still the resolved value.
const devOrgMembershipBaseURL = "http://localhost:8081"

// devTenderACLBaseURL is the local-dev default for iam-tender-acl (ADR-0007
// Wave 3 Phase 4 — I-12/GetTenderACL is repointed here from Org &
// Membership; GetMemberships/GetMFAFreshness (I-8/I-14) are unaffected and
// still call devOrgMembershipBaseURL above). Matches iam-tender-acl's own
// dev HTTP_PORT (8086, see its .env.example) — same fail-fast-outside-dev
// convention as devOrgMembershipBaseURL.
const devTenderACLBaseURL = "http://localhost:8086"

// Load reads Config from the environment, applying the same conventions as
// the rest of the IAM fleet (plain os.Getenv + default fallback, no
// viper/envconfig — see iam-user-profile's main.go envOr()).
func Load() (Config, error) {
	cfg := Config{
		AppName: envOr("APP_NAME", "iam-authz-enrichment"),
		AppEnv:  envOr("APP_ENV", "dev"),
		AppPort: envOr("APP_PORT", "8080"),
		// /metrics is served on its own dedicated port/listener, separate
		// from AppPort — mirrors iam-org-membership's/iam-tender-acl's/
		// iam-user-profile's/iam-catalog-admin's identical split. This
		// service's AppPort already carries no business API (healthz/
		// readyz/metrics only — the actual authz decision path is
		// exclusively gRPC), so the split is for fleet-wide consistency
		// rather than closing a NetworkPolicy gap here.
		MetricsPort: envOr("METRICS_PORT", "9090"),
		// 9091, not 9090 — 9090 is Prometheus's own conventional port and is
		// also commonly pre-bound by Docker Desktop's backend on macOS.
		GRPCPort: envOr("GRPC_PORT", "9091"),

		ValkeyURL: envOr("VALKEY_URL", "localhost:6379"),

		OrgMembershipBaseURL: envOr("ORG_MEMBERSHIP_BASE_URL", devOrgMembershipBaseURL),
		SharedRealmIssuer:    envOr("SHARED_REALM_ISSUER", ""),
		JWTMetadataNamespace: envOr("JWT_METADATA_NAMESPACE", "envoy.filters.http.jwt_authn"),
		JWTPayloadKey:        envOr("JWT_PAYLOAD_KEY", "trial"),

		TenderACLBaseURL: envOr("TENDER_ACL_BASE_URL", devTenderACLBaseURL),

		AWSRegion:      envOr("AWS_REGION", "ap-south-1"),
		AWSEndpointURL: envOr("AWS_ENDPOINT_URL", ""),

		MembershipQueueURL: envOr("MEMBERSHIP_AUTHZ_QUEUE_URL", ""),
		UserQueueURL:       envOr("USER_AUTHZ_QUEUE_URL", ""),
		BillingQueueURL:    envOr("BILLING_AUTHZ_QUEUE_URL", ""),
		TenantQueueURL:     envOr("TENANT_AUTHZ_QUEUE_URL", ""),
		TenderQueueURL:     envOr("TENDER_AUTHZ_QUEUE_URL", ""),

		GRPCTLSCertFile:     envOr("GRPC_TLS_CERT_FILE", ""),
		GRPCTLSKeyFile:      envOr("GRPC_TLS_KEY_FILE", ""),
		GRPCTLSClientCAFile: envOr("GRPC_TLS_CLIENT_CA_FILE", ""),

		DocsAuthToken: envOr("DOCS_AUTH_TOKEN", ""),
	}

	var err error
	if cfg.ValkeyDialTimeout, err = envDuration("VALKEY_DIAL_TIMEOUT", 20*time.Millisecond); err != nil {
		return Config{}, err
	}
	if cfg.ValkeyReadTimeout, err = envDuration("VALKEY_READ_TIMEOUT", 10*time.Millisecond); err != nil {
		return Config{}, err
	}
	if cfg.ValkeyWriteTimeout, err = envDuration("VALKEY_WRITE_TIMEOUT", 10*time.Millisecond); err != nil {
		return Config{}, err
	}
	if cfg.OrgMembershipTimeout, err = envDuration("ORG_MEMBERSHIP_TIMEOUT", 10*time.Millisecond); err != nil {
		return Config{}, err
	}
	if cfg.TenderACLTimeout, err = envDuration("TENDER_ACL_TIMEOUT", 20*time.Millisecond); err != nil {
		return Config{}, err
	}
	if cfg.AeCtxTTL, err = envDuration("AE_CTX_TTL", 60*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.AeCtxJitter, err = envDuration("AE_CTX_JITTER", 6*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.TenderACLTTL, err = envDuration("AE_TENDER_ACL_TTL", 15*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.NegativeCacheTTL, err = envDuration("AE_NEG_TTL", 5*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.ProcessedEventTTL, err = envDuration("AE_PROCESSED_EVENT_TTL", 7*24*time.Hour); err != nil {
		return Config{}, err
	}
	if cfg.StaleIfErrorMaxAge, err = envDuration("AE_STALE_IF_ERROR_MAX_AGE", staleIfErrorHardCap); err != nil {
		return Config{}, err
	}
	if cfg.StaleIfErrorMaxAge > staleIfErrorHardCap {
		cfg.StaleIfErrorMaxAge = staleIfErrorHardCap
	}

	if cfg.GRPCKeepAliveTime, err = envDuration("GRPC_KEEPALIVE_TIME", 30*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.GRPCKeepAliveTimeout, err = envDuration("GRPC_KEEPALIVE_TIMEOUT", 5*time.Second); err != nil {
		return Config{}, err
	}
	streams, err := envInt("GRPC_MAX_CONCURRENT_STREAMS", 1000)
	if err != nil {
		return Config{}, err
	}
	cfg.GRPCMaxConcurrentStreams = uint32(streams)

	// CheckRequest/CheckResponse payloads are small (a handful of claims and
	// six headers) — 256KiB is generous headroom, not a real operating
	// limit, kept far below gRPC-Go's 4MiB default as defense-in-depth
	// against a malformed or abusive message from a misbehaving Envoy
	// instance (§8: Envoy is trusted, but "trusted" isn't "unbounded").
	if cfg.GRPCMaxRecvMsgSizeBytes, err = envInt("GRPC_MAX_RECV_MSG_SIZE_BYTES", 256*1024); err != nil {
		return Config{}, err
	}
	if cfg.GRPCMaxSendMsgSizeBytes, err = envInt("GRPC_MAX_SEND_MSG_SIZE_BYTES", 256*1024); err != nil {
		return Config{}, err
	}

	if cfg.SQSMaxReceiveCount, err = envInt("SQS_MAX_RECEIVE_COUNT", 5); err != nil {
		return Config{}, err
	}

	if cfg.DocsEnabled, err = envBool("DOCS_ENABLED", false); err != nil {
		return Config{}, err
	}

	if cfg.MembershipQueueConcurrency, err = envInt("MEMBERSHIP_AUTHZ_QUEUE_CONCURRENCY", 4); err != nil {
		return Config{}, err
	}
	if cfg.UserQueueConcurrency, err = envInt("USER_AUTHZ_QUEUE_CONCURRENCY", 4); err != nil {
		return Config{}, err
	}
	if cfg.BillingQueueConcurrency, err = envInt("BILLING_AUTHZ_QUEUE_CONCURRENCY", 4); err != nil {
		return Config{}, err
	}
	if cfg.TenantQueueConcurrency, err = envInt("TENANT_AUTHZ_QUEUE_CONCURRENCY", 4); err != nil {
		return Config{}, err
	}
	if cfg.TenderQueueConcurrency, err = envInt("TENDER_AUTHZ_QUEUE_CONCURRENCY", 4); err != nil {
		return Config{}, err
	}

	seed := envOr("REALM_TENANT_MAP_SEED", "{}")
	cfg.RealmTenantMapSeed = map[string]string{}
	if err := json.Unmarshal([]byte(seed), &cfg.RealmTenantMapSeed); err != nil {
		return Config{}, fmt.Errorf("REALM_TENANT_MAP_SEED: invalid JSON: %w", err)
	}

	// ORG_MEMBERSHIP_BASE_URL left at its local-dev default outside dev is
	// never correct — there's no legitimate deployment where the Org &
	// Membership sibling actually runs at localhost:8081 inside this
	// service's own container. Left unchecked, the process starts, passes
	// health checks, and then silently fails every request that isn't a
	// cache hit — a startup crash-loop is far more visible and actionable
	// than that. SHARED_REALM_ISSUER has no equivalent check: it's
	// legitimately optional (ResolveTenant falls back to RealmTenantMapSeed
	// for dedicated-realm-only platforms — see tenant_resolve.go), so main.go
	// logs a warning for that case instead of failing here.
	if cfg.AppEnv != "dev" && cfg.OrgMembershipBaseURL == devOrgMembershipBaseURL {
		return Config{}, fmt.Errorf(
			"ORG_MEMBERSHIP_BASE_URL is left at its local-dev default (%s) with APP_ENV=%q — set it to the real Org & Membership service address",
			devOrgMembershipBaseURL, cfg.AppEnv,
		)
	}
	// Same fail-fast reasoning as ORG_MEMBERSHIP_BASE_URL above, for
	// iam-tender-acl (ADR-0007 Wave 3 Phase 4).
	if cfg.AppEnv != "dev" && cfg.TenderACLBaseURL == devTenderACLBaseURL {
		return Config{}, fmt.Errorf(
			"TENDER_ACL_BASE_URL is left at its local-dev default (%s) with APP_ENV=%q — set it to the real iam-tender-acl service address",
			devTenderACLBaseURL, cfg.AppEnv,
		)
	}

	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid duration %q: %w", key, v, err)
	}
	return d, nil
}

func envInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid integer %q: %w", key, v, err)
	}
	return n, nil
}

func envBool(key string, def bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: invalid boolean %q: %w", key, v, err)
	}
	return b, nil
}
