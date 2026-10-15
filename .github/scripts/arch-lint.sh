#!/usr/bin/env bash
# Runs go-arch-lint v1.15.0 against .go-arch-lint.yml to enforce component
# boundary rules. The binary is cached by the calling workflow at
# go-arch-lint-${{ runner.os }}-v1.15.0; this script installs it on a cache miss.
set -euo pipefail

cd "$(dirname "$0")/../.."

VERSION="v1.15.0"

if ! command -v go-arch-lint >/dev/null 2>&1; then
  echo "Installing go-arch-lint ${VERSION}…"
  go install "github.com/fe3dback/go-arch-lint@${VERSION}"
fi

echo "Running go-arch-lint ${VERSION}"
go-arch-lint check --project-path .
echo "arch-lint passed."
