#!/usr/bin/env bash
# check-golang-image-pin.sh — Dockerfile builder tag must match go.mod.
#
# go.mod's `go` directive is the source of truth. The builder image is
# `golang:<that>-alpine` (digest-pinned). A mismatch fails at
# `go mod download` with:
#   go: go.mod requires go >= X (running go Y; GOTOOLCHAIN=local)
# because the official golang image sets GOTOOLCHAIN=local and will not
# auto-fetch a newer toolchain.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

GO_VER=$(awk '/^go [0-9]/{print $2; exit}' go.mod)
if [ -z "$GO_VER" ]; then
  echo "::error file=go.mod,title=Go image pin::could not read go directive from go.mod"
  exit 1
fi

DF_TAG=$(grep -oE 'golang:[0-9]+\.[0-9]+\.[0-9]+-alpine' Dockerfile | head -1)
DIGEST_TAG=$(awk '/^golang:/{print $1; exit}' .docker-digests)
DF_DIGEST=$(grep -oE 'golang:[0-9]+\.[0-9]+\.[0-9]+-alpine@sha256:[0-9a-f]+' Dockerfile | head -1 | sed 's/.*@//')
FILE_DIGEST=$(awk '/^golang:/{print $2; exit}' .docker-digests)

FAIL=0
want="golang:${GO_VER}-alpine"

if [ "$DF_TAG" != "$want" ]; then
  echo "::error file=Dockerfile,title=Go image pin::Dockerfile builder is ${DF_TAG} but go.mod requires go ${GO_VER}. Run: make pin-base-images"
  FAIL=1
fi
if [ "$DIGEST_TAG" != "$want" ]; then
  echo "::error file=.docker-digests,title=Go image pin::.docker-digests lists ${DIGEST_TAG} but go.mod requires go ${GO_VER}. Run: make pin-base-images"
  FAIL=1
fi
if [ -n "$DF_DIGEST" ] && [ -n "$FILE_DIGEST" ] && [ "$DF_DIGEST" != "$FILE_DIGEST" ]; then
  echo "::error file=Dockerfile,title=Go image pin::Dockerfile digest ${DF_DIGEST} does not match .docker-digests ${FILE_DIGEST}"
  FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
echo "Go image pin: ${want} matches go.mod"
