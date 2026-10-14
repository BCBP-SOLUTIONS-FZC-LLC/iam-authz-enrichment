#!/usr/bin/env bash
# check-events-routing.sh — enforces that all events consumption, outbox
# config, and dedup processed-message handling in iam-authz-enrichment pass
# through platform-events only.
#
# Rules:
#   CONSUMERS   — all SQS consumer construction goes through
#                 events.NewSQSConsumerWithClient (via buildConsumer);
#                 no raw sqs.ReceiveMessage / sqs.DeleteMessage calls in
#                 internal/; AWS SDK imports confined to cmd/server.
#   CONFIG      — all consumer config assembled via config.SQSConfigFromEnv /
#                 config.SQSConsumerOptions / config.LoadSQS; no hand-rolled
#                 events.SQSConfig{} literals.
#   GLUE        — Glue wire-header stripping uses events.GlueDecodeCodec{}
#                 (platform-events built-in); no hand-rolled GlueDecoder in
#                 production code.
#   DEDUP       — processed-event idempotency uses Envelope.ID via
#                 MarkProcessed (SET NX); no separate IsProcessed call;
#                 EvictProcessed on failure so retries are real retries.
#   OUTBOX/SNS  — this service is consume-only (HLD §5.4 / EVT-2);
#                 cmd/server must never call events.NewSNSPublisher,
#                 outbox.ApplySchema, or outbox.NewRunner.
#   METRICS     — events.InitMetrics called with gincommon.MetricsRegisterer()
#                 so platform-events' own sqs_* counters land on the same
#                 /metrics registry (mirrors observability-lint).
#
# Mirrors check-observability-routing.sh and check-database-routing.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

FAIL=0
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}PASS${NC}  $1"; }
fail() { echo -e "  ${RED}FAIL${NC}  $1"; FAIL=1; }

echo "=== Events routing check: all events/outbox/dedup must pass through platform-events ==="
echo ""

# ────────────────────────────────────────────────────────────────────────────
# CONSUMERS — AWS SDK confined to cmd/server; internal/ uses SQSClientLike
# ────────────────────────────────────────────────────────────────────────────
echo "-- Consumers: AWS SDK imports confined to cmd/server (internal/ uses SQSClientLike) --"
AWS_IN_INTERNAL=$(grep -rn '"github.com/aws/aws-sdk-go' internal/ \
  --include="*.go" | grep -v "_test.go" || true)
if [ -n "$AWS_IN_INTERNAL" ]; then
  fail "Direct aws-sdk-go import in internal/ — internal packages must use the events.SQSClientLike interface, not the concrete SDK client:"
  echo "$AWS_IN_INTERNAL" | sed 's/^/    /'
else
  pass "No aws-sdk-go imports in internal/ (SDK client confined to cmd/server composition root)"
fi

echo "-- Consumers: no raw sqs.ReceiveMessage / sqs.DeleteMessage in internal/ --"
RAW_SQS_CALLS=$(grep -rn '\.ReceiveMessage\b\|\.DeleteMessage\b\|\.SendMessage\b' \
  internal/ --include="*.go" | grep -v "_test.go" || true)
if [ -n "$RAW_SQS_CALLS" ]; then
  fail "Raw SQS API call in internal/ — the platform-events consumer loop owns all ReceiveMessage/DeleteMessage calls:"
  echo "$RAW_SQS_CALLS" | sed 's/^/    /'
else
  pass "No raw SQS ReceiveMessage/DeleteMessage calls in internal/"
fi

echo "-- Consumers: all consumer construction via events.NewSQSConsumerWithClient --"
# events.NewSQSConsumer (no -WithClient) bypasses the SQSClientLike
# interface injection. All call sites must use the WithClient variant.
BARE_CONSUMER=$(grep -rn 'events\.NewSQSConsumer\b[^W]' internal/ cmd/ \
  --include="*.go" | grep -v "_test.go" | grep -v 'NewSQSConsumerWithClient' || true)
if [ -n "$BARE_CONSUMER" ]; then
  fail "events.NewSQSConsumer (without WithClient) found — use events.NewSQSConsumerWithClient so the SQS client is injected:"
  echo "$BARE_CONSUMER" | sed 's/^/    /'
else
  pass "All consumer construction uses events.NewSQSConsumerWithClient"
fi

# ────────────────────────────────────────────────────────────────────────────
# CONFIG — no hand-rolled SQSConfig; all config via platform-events helpers
# ────────────────────────────────────────────────────────────────────────────
echo "-- Config: no hand-rolled events.SQSConfig{} literals --"
RAW_SQS_CONFIG=$(grep -rn 'events\.SQSConfig{' internal/ cmd/ \
  --include="*.go" | grep -v "_test.go" || true)
if [ -n "$RAW_SQS_CONFIG" ]; then
  fail "Hand-rolled events.SQSConfig{} found — use config.SQSConfigFromEnv / config.SQSConsumerOptions instead:"
  echo "$RAW_SQS_CONFIG" | sed 's/^/    /'
else
  pass "No hand-rolled events.SQSConfig{} literals in production code"
fi

echo "-- Config: platform-events pkg/config used for SQS/SNS/outbox loading --"
# All config loading should go through config.LoadSQS / config.LoadSNS /
# config.LoadOutbox. A direct os.Getenv("SQS_QUEUE_URL") inside consumer/
# or internal/ is a bypass.
DIRECT_SQS_ENV=$(grep -rn 'os\.Getenv.*SQS_\|os\.Getenv.*SNS_\|os\.Getenv.*OUTBOX_' \
  internal/ --include="*.go" | grep -v "_test.go" || true)
if [ -n "$DIRECT_SQS_ENV" ]; then
  fail "Direct os.Getenv for SQS_*/SNS_*/OUTBOX_* in internal/ — use platform-events config.LoadSQS/LoadSNS/LoadOutbox:"
  echo "$DIRECT_SQS_ENV" | sed 's/^/    /'
else
  pass "No direct os.Getenv for SQS/SNS/OUTBOX env vars in internal/"
fi

# ────────────────────────────────────────────────────────────────────────────
# GLUE — platform-events built-in GlueDecodeCodec; no hand-rolled decoder
# ────────────────────────────────────────────────────────────────────────────
echo "-- Glue: events.GlueDecodeCodec{} used (no hand-rolled Glue decoder) --"
# glue_decoder.go was the hand-rolled decoder; it was deleted when
# platform-events v1.6.1 shipped events.GlueDecodeCodec. Catch any
# resurrection of a bespoke Glue-stripping type or function.
HAND_GLUE=$(grep -rn 'type GlueDecoder\b\|func.*GlueDecode\b\|glue_decoder\.go' \
  internal/ --include="*.go" | grep -v "_test.go" || true)
if [ -n "$HAND_GLUE" ]; then
  fail "Hand-rolled Glue decoder found — use events.GlueDecodeCodec{} via events.WithConsumerCodec (platform-events v1.6.1+):"
  echo "$HAND_GLUE" | sed 's/^/    /'
else
  pass "No hand-rolled Glue decoder (events.GlueDecodeCodec{} via platform-events is in use)"
fi

# Verify events.GlueDecodeCodec is actually wired into every consumer.
echo "-- Glue: events.WithConsumerCodec(events.GlueDecodeCodec{}) wired in buildConsumer --"
CODEC_WIRED=$(grep -c 'events\.GlueDecodeCodec{}' \
  internal/adapter/inbound/consumer/consumer.go 2>/dev/null || echo 0)
if [ "$CODEC_WIRED" -eq 0 ]; then
  fail "events.GlueDecodeCodec{} not wired in consumer.go buildConsumer — Glue-encoded envelopes will not be decoded:"
else
  pass "events.GlueDecodeCodec{} wired via events.WithConsumerCodec in buildConsumer"
fi

# ────────────────────────────────────────────────────────────────────────────
# DEDUP — Envelope.ID idempotency via MarkProcessed (SET NX); no IsProcessed
# ────────────────────────────────────────────────────────────────────────────
echo "-- Dedup: no IsProcessed method (MarkProcessed SET NX is the atomic check) --"
# Exclude comment-only lines (leading whitespace then // ).
IS_PROCESSED=$(grep -rn 'IsProcessed\b' internal/ cmd/ \
  --include="*.go" | grep -v "_test.go" | grep -v ':[[:space:]]*//' | grep -v '^[^:]*:[[:space:]]*//' || true)
if [ -n "$IS_PROCESSED" ]; then
  fail "IsProcessed call found — the MarkProcessed SET NX is itself the duplicate check; a separate read is a TOCTOU race:"
  echo "$IS_PROCESSED" | sed 's/^/    /'
else
  pass "No IsProcessed call (MarkProcessed SET NX is the atomic duplicate check)"
fi

echo "-- Dedup: EvictProcessed called on handler error AND panic (§16 AE-34) --"
EVICT_ON_ERR=$(grep -c 'EvictProcessed' \
  internal/adapter/inbound/consumer/idempotency.go 2>/dev/null || echo 0)
if [ "$EVICT_ON_ERR" -lt 2 ]; then
  fail "EvictProcessed should appear at least twice in idempotency.go (handler error path + panic recover path — §16 AE-34):"
  echo "    found $EVICT_ON_ERR occurrence(s) in internal/adapter/inbound/consumer/idempotency.go"
else
  pass "EvictProcessed called on both handler error and panic paths ($EVICT_ON_ERR occurrences)"
fi

echo "-- Dedup: Envelope.ID is the idempotency key (not message ID or body hash) --"
MSG_ID_DEDUP=$(grep -rn '\.MessageId\b.*MarkProcessed\|MarkProcessed.*\.MessageId\b' \
  internal/ --include="*.go" | grep -v "_test.go" || true)
if [ -n "$MSG_ID_DEDUP" ]; then
  fail "SQS MessageId used as idempotency key — must use Envelope.ID (platform-events' own dedup contract):"
  echo "$MSG_ID_DEDUP" | sed 's/^/    /'
else
  pass "Dedup keyed on Envelope.ID (not SQS MessageId)"
fi

# ────────────────────────────────────────────────────────────────────────────
# OUTBOX / SNS — consume-only invariant (HLD §5.4 / EVT-2)
# ────────────────────────────────────────────────────────────────────────────
echo "-- Outbox/SNS: cmd/server does not call NewSNSPublisher / outbox.NewRunner / outbox.ApplySchema (EVT-2) --"
PUBLISH_CALLS=$(grep -n 'events\.NewSNSPublisher\b\|outbox\.NewRunner\b\|outbox\.ApplySchema\b' \
  cmd/server/main.go 2>/dev/null | grep -v '^\s*//' | grep -v ':[[:space:]]*//' || true)
if [ -n "$PUBLISH_CALLS" ]; then
  fail "cmd/server/main.go calls NewSNSPublisher / outbox.NewRunner / outbox.ApplySchema — this service is consume-only (HLD §5.4 / EVT-2):"
  echo "$PUBLISH_CALLS" | sed 's/^/    /'
else
  pass "cmd/server/main.go correctly skips NewSNSPublisher / outbox.NewRunner / outbox.ApplySchema (consume-only)"
fi

echo "-- Outbox/SNS: no outbox.NewRunner or events.NewSNSPublisher in internal/ --"
# Exclude comment-only lines (leading optional whitespace then //).
INTERNAL_PUBLISH=$(grep -rn 'outbox\.NewRunner\b\|events\.NewSNSPublisher\b' \
  internal/ --include="*.go" | grep -v "_test.go" | \
  grep -v ':[[:space:]]*//' | grep -v '^[^:]*:[[:space:]]*//' || true)
if [ -n "$INTERNAL_PUBLISH" ]; then
  fail "outbox.NewRunner / events.NewSNSPublisher found in internal/ — this service publishes no events (HLD §5.4 / EVT-2):"
  echo "$INTERNAL_PUBLISH" | sed 's/^/    /'
else
  pass "No outbox.NewRunner / events.NewSNSPublisher in internal/"
fi

# ────────────────────────────────────────────────────────────────────────────
# METRICS — events.InitMetrics must use gincommon.MetricsRegisterer()
# ────────────────────────────────────────────────────────────────────────────
echo "-- Metrics: events.InitMetrics wired to gincommon.MetricsRegisterer() --"
INIT_METRICS=$(grep -n 'events\.InitMetrics' cmd/server/main.go 2>/dev/null || true)
if [ -z "$INIT_METRICS" ]; then
  fail "events.InitMetrics not called in cmd/server/main.go — platform-events sqs_* counters will not appear on /metrics:"
else
  # Verify it references gincommon.MetricsRegisterer() on the same line or nearby
  METRICS_WITH_GINCOMMON=$(grep -n 'events\.InitMetrics.*gincommon\.MetricsRegisterer\|gincommon\.MetricsRegisterer.*events\.InitMetrics' \
    cmd/server/main.go 2>/dev/null || true)
  if [ -z "$METRICS_WITH_GINCOMMON" ]; then
    fail "events.InitMetrics found but not passed gincommon.MetricsRegisterer() — sqs_* metrics will land on a different registry:"
    echo "$INIT_METRICS" | sed 's/^/    /'
  else
    pass "events.InitMetrics wired to gincommon.MetricsRegisterer()"
  fi
fi

# ────────────────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────────────────
echo ""
if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}All events routing checks passed.${NC}"
  echo "  Consumers → events.NewSQSConsumerWithClient via buildConsumer"
  echo "  Config    → config.LoadSQS / SQSConfigFromEnv / SQSConsumerOptions"
  echo "  Glue      → events.GlueDecodeCodec{} via events.WithConsumerCodec"
  echo "  Dedup     → Envelope.ID via MarkProcessed SET NX + EvictProcessed on error/panic"
  echo "  Outbox    → skipped (consume-only, HLD §5.4 / EVT-2)"
  echo "  Metrics   → events.InitMetrics → gincommon.MetricsRegisterer()"
  exit 0
else
  echo -e "${RED}Events routing check FAILED — see violations above.${NC}"
  echo "All events consumption, outbox config, and dedup must pass through platform-events only."
  exit 1
fi
