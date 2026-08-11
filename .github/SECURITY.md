# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Active |

Older major versions are not patched. Deploy the latest 1.x image.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: vijay@bcbpsolutions.com
Subject: `[iam-authz-enrichment] Security vulnerability`

Include in your report:
- Description of the vulnerability and the affected component (gRPC `Check` handler, cache adapter, event consumer, Org & Membership client, etc.)
- Steps to reproduce
- Potential impact (unauthorized Allow, cross-tenant data leakage, identity spoofing, privilege escalation, DoS, etc.)
- Suggested fix or patch (if any)

### Response timeline

| Step | Target |
|------|--------|
| Initial acknowledgement | 48 hours |
| Severity assessment | 5 business days |
| Patch release (critical/high) | 14 days |
| Public disclosure | After patch ships |

We follow responsible disclosure. Reporters will be credited in release notes unless anonymity is requested.

## Scope

Areas of particular sensitivity in this service — see [`ARCHITECTURE.md` § Threat model](../ARCHITECTURE.md#threat-model) for the full STRIDE analysis:

- **Identity source** — this service reads identity *only* from Envoy's `jwt_authn`-validated dynamic metadata (`CheckRequest.Attributes.MetadataContext`), never from request headers. A code path that falls back to a client-supplied header would allow identity spoofing.
- **Header injection** — the six output headers (`x-user-id`, `x-departments`, etc.) must be built exclusively from server-side cached/fetched data. A path where inbound headers leak into the response would let a caller forge its own authorization context.
- **`mfa_freshness_seconds` caching** — this value must never be cached (§4.4/§8.3). A regression that folds it into the `ae:ctx` envelope would let a tenant's MFA-freshness tightening take up to 60s to take effect instead of immediately.
- **Tenant scoping** — every Valkey key and outbound call is tenant-scoped by construction; there is no separate access-control layer, since there is no database. A key-building bug that drops the tenant segment is a cross-tenant data leak.
- **Fail-closed vs. bypass** — the §7 failure-handling matrix and the tender-ACL overlay's independent fail-closed rule determine whether a dependency outage denies or bypasses a check. A miscategorized dependency failure could silently turn a fail-closed path into an open one.
- **Log redaction** — only `sub`/`iss` are ever logged. A code path that logs `auth_time` or any other raw claim is a PII/security-relevant regression, enforced by construction rather than a sanitizer.
