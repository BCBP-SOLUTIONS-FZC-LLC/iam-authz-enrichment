#!/usr/bin/env python3
"""Render deploy/helm/templates/prometheusrule.yaml from deploy/monitoring/app-alerts.yml.

app-alerts.yml is the single source of truth for this service's alert rules;
the Helm PrometheusRule is generated from it so the two cannot drift:

  - the rule groups are copied verbatim, re-indented under spec.groups;
  - job="iam-authz-enrichment" becomes the release's fullname (the
    ServiceMonitor's job label);
  - Prometheus template expressions ({{ $value }}, {{ $labels.x }}) are escaped
    so Helm passes them through untouched.

Usage:
  render-prometheusrule.py           # rewrite the Helm template
  render-prometheusrule.py --check   # exit 1 if it is out of date (CI)
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "deploy/monitoring/app-alerts.yml"
DST = ROOT / "deploy/helm/templates/prometheusrule.yaml"

HEADER = """{{- /*
  GENERATED from deploy/monitoring/app-alerts.yml by
  .github/scripts/render-prometheusrule.py (`make prometheusrule`).
  Do not edit by hand; CI fails when this file is out of date.
*/ -}}
{{- if .Values.serviceMonitor.enabled }}
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: {{ include "iam-authz-enrichment.fullname" . }}
  labels:
    {{- include "iam-authz-enrichment.labels" . | nindent 4 }}
    {{- with .Values.serviceMonitor.additionalLabels }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
spec:
  groups:
"""
FOOTER = "{{- end }}\n"
JOB = 'job="iam-authz-enrichment"'
HELM_JOB = 'job={{ include "iam-authz-enrichment.fullname" . | quote }}'


def render() -> str:
    lines = SRC.read_text().splitlines()
    try:
        start = lines.index("groups:") + 1
    except ValueError:
        sys.exit(f"{SRC}: no top-level 'groups:' key")
    body = []
    for line in lines[start:]:
        # Escape Prometheus templating first, then insert Helm's own.
        line = re.sub(r"\{\{(\s*\$[^}]*?)\}\}", lambda m: '{{ "{{' + m.group(1) + '}}" }}', line)
        line = line.replace(JOB, HELM_JOB)
        body.append(("  " + line) if line.strip() else "")
    while body and not body[-1]:
        body.pop()
    return HEADER + "\n".join(body) + "\n" + FOOTER


def main() -> int:
    out = render()
    if "--check" in sys.argv[1:]:
        if not DST.exists() or DST.read_text() != out:
            print(f"{DST.relative_to(ROOT)} is out of date with {SRC.relative_to(ROOT)} — run `make prometheusrule`", file=sys.stderr)
            return 1
        return 0
    DST.write_text(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
