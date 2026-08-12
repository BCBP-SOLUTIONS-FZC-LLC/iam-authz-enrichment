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
	AppName  string
	AppEnv   string
	AppPort  string
	GRPCPort string

	ValkeyURL          string
	ValkeyDialTimeout  time.Duration
	ValkeyReadTimeout  time.Duration
	ValkeyWriteTimeout time.Duration

	OrgMembershipBaseURL string
	OrgMembershipTimeout time.Duration

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

	AWSRegion      string
	AWSEndpointURL string // LocalStack endpoint override; empty in real AWS

	MembershipQueueURL string
	UserQueueURL       string
	BillingQueueURL    string
	TenantQueueURL     string
	TenderQueueURL     string
	SQSMaxReceiveCount int

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

// Load reads Config from the environment, applying the same conventions as
// the rest of the IAM fleet (plain os.Getenv + default fallback, no
// viper/envconfig — see iam-user-profile's main.go envOr()).
func Load() (Config, error) {
	cfg := Config{
		AppName: envOr("APP_NAME", "iam-authz-enrichment"),
		AppEnv:  envOr("APP_ENV", "dev"),
		AppPort: envOr("APP_PORT", "8080"),
		// 9091, not 9090 — 9090 is Prometheus's own conventional port and is
		// also commonly pre-bound by Docker Desktop's backend on macOS.
		GRPCPort: envOr("GRPC_PORT", "9091"),

		ValkeyURL: envOr("VALKEY_URL", "localhost:6379"),

		OrgMembershipBaseURL: envOr("ORG_MEMBERSHIP_BASE_URL", "http://localhost:8081"),
		SharedRealmIssuer:    envOr("SHARED_REALM_ISSUER", ""),
		JWTMetadataNamespace: envOr("JWT_METADATA_NAMESPACE", "envoy.filters.http.jwt_authn"),
		JWTPayloadKey:        envOr("JWT_PAYLOAD_KEY", "trial"),

		AWSRegion:      envOr("AWS_REGION", "ap-south-1"),
		AWSEndpointURL: envOr("AWS_ENDPOINT_URL", ""),

		MembershipQueueURL: envOr("MEMBERSHIP_AUTHZ_QUEUE_URL", ""),
		UserQueueURL:       envOr("USER_AUTHZ_QUEUE_URL", ""),
		BillingQueueURL:    envOr("BILLING_AUTHZ_QUEUE_URL", ""),
		TenantQueueURL:     envOr("TENANT_AUTHZ_QUEUE_URL", ""),
		TenderQueueURL:     envOr("TENDER_AUTHZ_QUEUE_URL", ""),
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

	if cfg.SQSMaxReceiveCount, err = envInt("SQS_MAX_RECEIVE_COUNT", 5); err != nil {
		return Config{}, err
	}

	seed := envOr("REALM_TENANT_MAP_SEED", "{}")
	cfg.RealmTenantMapSeed = map[string]string{}
	if err := json.Unmarshal([]byte(seed), &cfg.RealmTenantMapSeed); err != nil {
		return Config{}, fmt.Errorf("REALM_TENANT_MAP_SEED: invalid JSON: %w", err)
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
