#!/usr/bin/env bash
# PreToolUse (Edit|Write|MultiEdit|NotebookEdit): block hand edits to files
# that are generated (CLAUDE.md: "never edit by hand") and to the local .env.
# Exit 2 blocks the tool call and shows the reason to Claude.
set -euo pipefail

f=$(jq -r '.tool_input.file_path // .tool_input.notebook_path // empty')
[ -n "$f" ] || exit 0
rel=${f#"${CLAUDE_PROJECT_DIR:-$PWD}"/}

case "$rel" in
  docs/observability/metric-registry.md)
    echo "Blocked: $rel is generated. Change the collectors/registry, then run \`make metrics-inventory\`." >&2
    exit 2 ;;
  deploy/helm/templates/prometheusrule.yaml)
    echo "Blocked: $rel is generated. Edit deploy/monitoring/app-alerts.yml, then run \`make prometheusrule\`." >&2
    exit 2 ;;
  .env)
    echo "Blocked: .env is the developer's local config (may hold secrets). Change .env-example instead, or ask the user to edit .env." >&2
    exit 2 ;;
esac
