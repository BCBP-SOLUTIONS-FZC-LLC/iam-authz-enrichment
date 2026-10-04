#!/usr/bin/env bash
# govulncheck over the WHOLE module (./...) — including cmd/server, where the
# gRPC/HTTP servers are started. The previous ./internal/... scope missed a
# reachable grpc server vulnerability whose call path starts in cmd/server.
#
# Fails on any vulnerability govulncheck finds reachable from this code,
# unless it is listed, unexpired, in .github/govulncheck-allow.txt.
set -euo pipefail

cd "$(dirname "$0")/../.."

allow_file=.github/govulncheck-allow.txt
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

set +e
go run golang.org/x/vuln/cmd/govulncheck@latest -format json ./... >"$work/out.json"
rc=$?
set -e
if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
  echo "govulncheck failed to run (exit $rc)" >&2
  exit "$rc"
fi

python3 - "$work/out.json" "$allow_file" <<'PYEOF'
import datetime
import json
import sys

out_path, allow_path = sys.argv[1:]
today = datetime.date.today()

allowed, expired = {}, {}
for raw in open(allow_path, encoding="utf-8"):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    osv, expires, *reason = line.split()
    exp = datetime.date.fromisoformat(expires)
    (allowed if exp >= today else expired)[osv] = (exp, " ".join(reason))

# The JSON stream is a sequence of objects; a "finding" whose trace reaches a
# function (trace[0] has "function") is a vulnerability this code calls.
dec = json.JSONDecoder()
text = open(out_path, encoding="utf-8").read()
idx, called = 0, set()
while idx < len(text):
    while idx < len(text) and text[idx].isspace():
        idx += 1
    if idx >= len(text):
        break
    obj, idx = dec.raw_decode(text, idx)
    f = obj.get("finding")
    if f and f.get("trace") and f["trace"][0].get("function"):
        called.add(f["osv"])

fail = False
for osv in sorted(called):
    if osv in allowed:
        exp, reason = allowed[osv]
        print(f"ALLOWED  {osv} (until {exp}): {reason}")
    elif osv in expired:
        exp, reason = expired[osv]
        print(f"::error::{osv} is reachable and its exception expired on {exp} — upgrade or re-justify in {allow_path}")
        fail = True
    else:
        print(f"::error::{osv} is reachable from this code — run `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` for the trace")
        fail = True
stale = sorted(set(allowed) - called)
for osv in stale:
    print(f"NOTE     {osv} is allow-listed but no longer reachable — remove it from {allow_path}")
if fail:
    sys.exit(1)
print(f"vuln-check passed: {len(called)} reachable vulnerability(ies), all accepted until their expiry")
PYEOF
