#!/usr/bin/env bash
# PostToolUse (Edit|Write|MultiEdit): gofmt the edited .go file in place, so
# `make fmt-check` (pre-commit and CI) never fails on Claude's edits.
# A gofmt parse error is fed back to Claude (exit 2) so it fixes the syntax.
set -euo pipefail

f=$(jq -r '.tool_input.file_path // empty')
case "$f" in
  *.go) ;;
  *) exit 0 ;;
esac
[ -f "$f" ] || exit 0

if ! out=$(gofmt -w "$f" 2>&1); then
  echo "gofmt failed on $f:" >&2
  echo "$out" >&2
  exit 2
fi
