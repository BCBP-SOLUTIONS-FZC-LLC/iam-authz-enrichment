---
name: Bug report
about: Report a defect in the iam-authz-enrichment service (ext_authz decisions, caching, or event consumption)
title: '[BUG] '
labels: bug
assignees: ''
---

## Description
A clear description of the bug.

## Service version
`github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment` — tag / commit SHA:

## Go version
`go version goX.Y.Z ...`

## Environment
- [ ] Local dev (`make run`)
- [ ] Docker Compose (`make docker-up`)
- [ ] Staging
- [ ] Production

## Affected area
- [ ] `Authorization.Check` gRPC decision (which `DenyReason`, or an incorrect Allow?)
- [ ] §3.1 precedence chain (base role/department policy, tender-ACL overlay, MFA-freshness gate)
- [ ] Cache (Valkey — `ae:ctx` / `ae:tenant` / `ae:tender_acl` / `ae:neg` / `ae:processed`)
- [ ] Event consumption (queue: `membership-authz-q` / `user-authz-q` / `billing-authz-q` / `tenant-authz-q` / `tender-authz-q`)
- [ ] §7 failure handling (bypass / stale-if-error / fail-closed)
- [ ] Tenant resolution (realm → tenant map)

## Steps to reproduce
1.
2.
3.

## Expected behaviour
What you expected the `CheckResponse` (Allow/Deny + reason/headers) to be.

## Actual behaviour
What actually happened. Include the `DenyReason`, injected headers, HTTP status codes, or gRPC error, plus log output.

```
// paste relevant log output, grpcurl request/response, or stack trace here
```

## Minimal reproduction
```sh
# paste the grpcurl command (CheckRequest JSON) that triggers the bug
```

## Additional context
Any other relevant context (Valkey key contents at time of failure, event ID / payload that triggered an eviction, `ORG_MEMBERSHIP_BASE_URL` response, related issues).
