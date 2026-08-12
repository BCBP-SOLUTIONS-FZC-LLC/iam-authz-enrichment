#!/usr/bin/env bash
# Downloads SLSA provenance attestation from GHCR and writes provenance.slsa.json.
set -euo pipefail
set -o pipefail

: "${IMAGE_NAME:?IMAGE_NAME is required}"
: "${IMAGE_DIGEST:?IMAGE_DIGEST is required}"

IMAGE_REF="${IMAGE_NAME}@${IMAGE_DIGEST}"

# provenance/v0.2, not v1: docker/build-push-action's `provenance: mode=max`
# shorthand maps to buildx's default --provenance flag, which emits SLSA
# schema v0.2 (https://docs.docker.com/build/metadata/attestations/slsa-provenance/)
# unless the build step explicitly opts into version=v1 via the longer
# `--attest type=provenance,mode=max,version=v1` form, which release.yml
# does not use. Filtering by predicate-type (rather than fetching
# unfiltered) matters here: this image also carries a separate SBOM
# attestation (from `sbom: true` on the same build step) — an unfiltered
# `cosign download attestation` would return both, and `.[0]` could just as
# easily grab the SBOM payload instead of the provenance one.
if ! cosign download attestation \
  --predicate-type=https://slsa.dev/provenance/v0.2 \
  "${IMAGE_REF}" \
  | jq -er 'if type == "array" then .[0].payload else .payload end' \
  | base64 -d \
  | jq . \
  | tee provenance.slsa.json >/dev/null; then
  echo "::error title=Provenance export::SLSA provenance attestation not found on ${IMAGE_REF}"
  exit 1
fi

echo "  ✔  exported SLSA provenance to provenance.slsa.json"
