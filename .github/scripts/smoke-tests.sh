#!/usr/bin/env bash
# Image size + liveness gate for the CI-built Docker image.
# Invoked by ci.yml (keeps shell operators out of inline YAML run blocks).
#
# Unlike iam-user-profile's smoke test, this service has no *required* env
# vars — every config.Load() field defaults (§ config/config.go) so a
# container with an empty environment still starts and serves /healthz.
# That's why the gate here is "does it come up and answer /healthz", not
# "does it exit non-zero on missing config".
set -euo pipefail

echo "::group::Image size check (linux/amd64)"
MAX_MB=200
size=$(docker image inspect iam-authz-enrichment-ci-test --format='{{.Size}}')
mb=$((size / 1024 / 1024))
echo "Image size: ${mb} MB (limit: ${MAX_MB} MB)"
echo "::endgroup::"

echo "::group::Liveness gate"
CID=$(docker run -d --rm -p 18080:8080 iam-authz-enrichment-ci-test)
trap 'docker stop "${CID}" >/dev/null 2>&1 || true' EXIT

ok=0
for _ in $(seq 1 20); do
  if curl -sf http://localhost:18080/healthz >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.5
done
echo "::endgroup::"

{
  echo "### Smoke test results"
  if [ "${ok}" -eq 1 ]; then
    echo "- ✅ Liveness gate: /healthz responded within 10s of container start"
  else
    echo "- ❌ Liveness gate: /healthz did not respond within 10s"
  fi
  echo "- 📦 Image size (linux/amd64): **${mb} MB** (limit: ${MAX_MB} MB)"
} >> "$GITHUB_STEP_SUMMARY"

if [ "${mb}" -gt "${MAX_MB}" ]; then
  echo "::error file=Dockerfile,title=Image size::Image is ${mb} MB, exceeds ${MAX_MB} MB limit — check COPY/ADD instructions for accidental inclusions"
  exit 1
fi
if [ "${ok}" -ne 1 ]; then
  echo "::error file=cmd/server/main.go,title=Liveness gate::/healthz did not respond within 10s of container start"
  exit 1
fi
