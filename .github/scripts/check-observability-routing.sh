#!/usr/bin/env bash
# check-observability-routing.sh — enforces that all logs, metrics, and traces
# in iam-authz-enrichment pass through platform-gincommon only.
#
# Rules:
#   LOGS    — no direct go.uber.org/zap usage outside vendor; no stdlib
#             log.Printf/log.Println/log.Fatal outside cmd/server/main.go's
#             main() bootstrap (the one place before the Zap logger exists).
#   METRICS — no prometheus.MustRegister / prometheus.Register calls outside
#             the platform-gincommon-backed metrics/recorder.go; no raw
#             prometheus.NewRegistry() outside test files.
#   TRACES  — no otel.SetTracerProvider() outside gincommon; no sdktrace
#             .NewTracerProvider() outside gincommon or test files.
#
# Mirrors the equivalent checks in iam-org-membership and iam-user-profile.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

FAIL=0
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}PASS${NC}  $1"; }
fail() { echo -e "  ${RED}FAIL${NC}  $1"; FAIL=1; }

echo "=== Observability routing check: all logs/metrics/traces must pass through platform-gincommon ==="
echo ""

# ────────────────────────────────────────────────────────────────────────────
# LOGS — no direct go.uber.org/zap import in internal/ or cmd/
# ────────────────────────────────────────────────────────────────────────────
echo "-- Logs: no direct go.uber.org/zap import --"
ZAP_VIOLATIONS=$(grep -rn '"go.uber.org/zap"' internal/ cmd/ \
  --include="*.go" | grep -v "_test.go" || true)
if [ -n "$ZAP_VIOLATIONS" ]; then
  fail "Direct go.uber.org/zap import found — use platform-gincommon/pkg/logger.NewLogger instead:"
  echo "$ZAP_VIOLATIONS" | sed 's/^/    /'
else
  pass "No direct go.uber.org/zap imports in internal/ or cmd/"
fi

# ────────────────────────────────────────────────────────────────────────────
# LOGS — no stdlib log.Printf / log.Println / log.Fatal outside main()
# Allowed only in cmd/server/main.go's main() entrypoint (before Zap exists).
# ────────────────────────────────────────────────────────────────────────────
echo "-- Logs: stdlib log package only in main() bootstrap --"
STDLIB_LOG=$(grep -rn '\blog\.Printf\b\|\blog\.Println\b\|\blog\.Fatal\b\|\blog\.Print\b' \
  internal/ cmd/ --include="*.go" | grep -v "_test.go" | \
  grep -v "cmd/server/main.go" || true)
if [ -n "$STDLIB_LOG" ]; then
  fail "Stdlib log.* calls found outside cmd/server/main.go — use the Logger interface (gincommon-backed) instead:"
  echo "$STDLIB_LOG" | sed 's/^/    /'
else
  pass "No stdlib log.* calls outside main() bootstrap"
fi

# ────────────────────────────────────────────────────────────────────────────
# METRICS — no prometheus.MustRegister / prometheus.Register outside recorder.go
# All registration must go through promauto.With(gincommon.MetricsRegisterer()).
# ────────────────────────────────────────────────────────────────────────────
echo "-- Metrics: all registration through gincommon.MetricsRegisterer() --"
RAW_REGISTER=$(grep -rn 'prometheus\.MustRegister\|prometheus\.DefaultRegisterer\.Register\b' \
  internal/ cmd/ --include="*.go" | grep -v "_test.go" || true)
if [ -n "$RAW_REGISTER" ]; then
  fail "Raw prometheus.MustRegister/DefaultRegisterer.Register found — use promauto.With(gincommon.MetricsRegisterer()) instead:"
  echo "$RAW_REGISTER" | sed 's/^/    /'
else
  pass "No raw prometheus.MustRegister / DefaultRegisterer.Register calls"
fi

echo "-- Metrics: no prometheus.NewRegistry() in production code --"
# Exclude comment-only lines (lines whose non-whitespace content starts with //)
RAW_REGISTRY=$(grep -rn 'prometheus\.NewRegistry()' internal/ cmd/ \
  --include="*.go" | grep -v "_test.go" | grep -v '^\s*//' | \
  grep -v ':[[:space:]]*//' || true)
if [ -n "$RAW_REGISTRY" ]; then
  fail "prometheus.NewRegistry() found in production code — only test files may create isolated registries:"
  echo "$RAW_REGISTRY" | sed 's/^/    /'
else
  pass "No prometheus.NewRegistry() in production code"
fi

echo "-- Metrics: /metrics handler uses gincommon.MetricsRegisterer() only --"
HANDLER_FALLBACK=$(grep -n 'promhttp\.Handler()' cmd/server/main.go || true)
if [ -n "$HANDLER_FALLBACK" ]; then
  fail "promhttp.Handler() (DefaultGatherer) found in main.go — metricsScrapeHandler must use gincommon.MetricsRegisterer():"
  echo "$HANDLER_FALLBACK" | sed 's/^/    /'
else
  pass "metricsScrapeHandler uses gincommon.MetricsRegisterer() only"
fi

# ────────────────────────────────────────────────────────────────────────────
# TRACES — no otel.SetTracerProvider() outside gincommon
# gincommon.InitTracingFromEnv() owns the global TracerProvider; setting it
# directly in application code would break distributed trace continuity.
# ────────────────────────────────────────────────────────────────────────────
echo "-- Traces: no otel.SetTracerProvider() outside gincommon --"
SET_PROVIDER=$(grep -rn 'otel\.SetTracerProvider\b' internal/ cmd/ \
  --include="*.go" | grep -v "_test.go" || true)
if [ -n "$SET_PROVIDER" ]; then
  fail "otel.SetTracerProvider() found in application code — use gincommon.InitTracingFromEnv() in main.go only:"
  echo "$SET_PROVIDER" | sed 's/^/    /'
else
  pass "No otel.SetTracerProvider() calls in application code"
fi

echo "-- Traces: no sdktrace.NewTracerProvider() in production code --"
SDK_PROVIDER=$(grep -rn 'sdktrace\.NewTracerProvider\|sdk/trace.*NewTracerProvider' \
  internal/ cmd/ --include="*.go" | grep -v "_test.go" || true)
if [ -n "$SDK_PROVIDER" ]; then
  fail "sdktrace.NewTracerProvider() found in production code — gincommon.InitTracingFromEnv() owns the provider:"
  echo "$SDK_PROVIDER" | sed 's/^/    /'
else
  pass "No sdktrace.NewTracerProvider() in production code"
fi

# ────────────────────────────────────────────────────────────────────────────
# TRACES — outbound HTTP calls must use otelhttp transport (gincommon's propagator)
# ────────────────────────────────────────────────────────────────────────────
echo "-- Traces: outbound HTTP clients use otelhttp transport --"
# Look for http.DefaultTransport used directly (NOT as the argument to
# otelhttp.NewTransport). A line containing otelhttp.NewTransport is correct;
# a bare http.DefaultTransport outside that context is a violation.
RAW_HTTP=$(grep -rn 'http\.DefaultTransport\b' internal/ \
  --include="*.go" | grep -v "_test.go" | \
  grep -v "otelhttp\.NewTransport" || true)
if [ -n "$RAW_HTTP" ]; then
  fail "http.DefaultTransport used without otelhttp.NewTransport wrapping — trace propagation will break:"
  echo "$RAW_HTTP" | sed 's/^/    /'
else
  pass "All outbound HTTP clients use otelhttp-instrumented transport"
fi

# ────────────────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────────────────
echo ""
if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}All observability routing checks passed.${NC}"
  echo "  Logs    → platform-gincommon/pkg/logger.NewLogger"
  echo "  Metrics → gincommon.MetricsRegisterer() via promauto.With()"
  echo "  Traces  → gincommon.InitTracingFromEnv() global TracerProvider"
  exit 0
else
  echo -e "${RED}Observability routing check FAILED — see violations above.${NC}"
  echo "All logs, metrics, and traces must pass through platform-gincommon only."
  exit 1
fi
