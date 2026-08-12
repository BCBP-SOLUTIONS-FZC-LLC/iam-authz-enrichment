#!/usr/bin/env bash
# Cross-compiles release binaries for all target platforms and writes per-binary
# checksums. The artifact directory is the working directory when this runs.
#
# Produces for each platform:
#   iam-authz-enrichment_{version}_{os}_{arch}[.exe]
#   iam-authz-enrichment_{version}_{os}_{arch}[.exe].sha256
#
# The caller (create-github-release.sh) aggregates the .sha256 files into
# a single checksums.txt with `sha256sum iam-authz-enrichment_* | grep -v '\.sha256$'`.
#
# This service is deployed exclusively as a container (README § Out of
# scope) — these binaries are a convenience for local/non-Docker runs, not
# the primary distribution artifact (that's the signed GHCR image).
set -euo pipefail

: "${RELEASE_TAG:?RELEASE_TAG is required}"

TARGETS=(
  "linux   amd64"
  "linux   arm64"
  "darwin  amd64"
  "darwin  arm64"
  "windows amd64"
)

echo "Building release binaries for tag ${RELEASE_TAG}"

for target in "${TARGETS[@]}"; do
  read -r GOOS GOARCH <<< "$target"
  EXT=""
  [ "${GOOS}" = "windows" ] && EXT=".exe"
  ASSET_NAME="iam-authz-enrichment_${RELEASE_TAG}_${GOOS}_${GOARCH}${EXT}"

  echo "  → ${GOOS}/${GOARCH}"
  CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
    go build -trimpath \
      -ldflags "-s -w -X main.buildVersion=${RELEASE_TAG}" \
      -o "${ASSET_NAME}" \
      ./cmd/server

  chmod +x "${ASSET_NAME}"
  sha256sum "${ASSET_NAME}" > "${ASSET_NAME}.sha256"
  echo "    ✔  ${ASSET_NAME}"
done

# Write the primary asset name (linux/amd64) for downstream steps that
# need a single canonical file reference.
echo "iam-authz-enrichment_${RELEASE_TAG}_linux_amd64" > release-asset.name
echo "All binaries prepared."
