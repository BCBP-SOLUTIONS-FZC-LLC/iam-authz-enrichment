---
name: Feature request
about: Propose a new precedence step, cached value, event type, or service behaviour
title: '[FEAT] '
labels: enhancement
assignees: ''
---

## Problem / motivation
What problem does this solve? Which downstream service behind the Envoy `ext_authz` filter is affected?

## Proposed solution
Describe the behaviour change you'd like.

```go
// Example: new RequestFacts field, DenyReason, or cache key
```

## Affected areas
- [ ] §3.1 precedence chain (new or reordered check)
- [ ] Domain model (new `DenyReason`, `RequestFacts` field, or value object)
- [ ] Cache strategy (new key, changed TTL, or a value that must never be cached)
- [ ] Event contract (new §5 event type or changed payload — coordinate with the publishing service's team)
- [ ] Org & Membership client (new I-8/I-12/I-14-style call)
- [ ] Observability (new metric or span)

## Event contract impact
If this adds or changes a consumed event type, describe the impact on the publishing service (Membership, User, Billing, Tenant, or Tender) and whether a coordinated deploy order is required.

## Alternatives considered
Other approaches you evaluated and why you ruled them out.

## Acceptance criteria
- [ ]
- [ ]
- [ ]

## Additional context
Links to related issues, the LLD, ADRs, or prior art.
