
## Description
Provide a clear description of the changes.

---

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Refactor
- [ ] Documentation
- [ ] Test
- [ ] Breaking change
- [ ] Event contract change (new/changed §5 consumed event)

---

## Testing
- [ ] Unit tests added/updated (`make test`)
- [ ] Integration tests added/updated (`make test-integration`, requires `make docker-up`)
- [ ] E2E tests added/updated if the `Check` wire contract, an env var, or the precedence chain changed (`make build && make test-e2e`, requires `make docker-up`)
- [ ] All tests passing with race detector (`make race`)
- [ ] Manual `grpcurl`/`grpcui` testing performed (if the `Check` request/response shape changed)

---

## Checklist

### Code Quality
- [ ] Code is properly formatted (`make fmt-check`)
- [ ] Linting passed (`make lint`)
- [ ] Vet passed (`make vet`)
- [ ] Arch-lint passed (`make arch-lint`)
- [ ] No debug logs / commented-out code
- [ ] No secrets hardcoded

### §3.1 Precedence Chain
*Complete only when `internal/usecase/check.go` or `internal/domain/policy/` changed.*

- [ ] Existing step order preserved, or the reorder is intentional and documented
- [ ] A precedence-order test added: a request failing this check **and** a later one resolves to this step's `DenyReason`, not the later one's
- [ ] `ARCHITECTURE.md` precedence table and `docs/architecture/mermaid/request-flow.mmd` updated if the chain changed

### Caching (§4)
*Complete only when `internal/adapter/outbound/valkey/` changed.*

- [ ] New/changed key added to the §4 key table in `README.md` / `ARCHITECTURE.md`
- [ ] Confirmed the value is safe to cache — anything that must react immediately to a tenant-side change (like `mfa_freshness_seconds`) must **never** be cached, with a regression test asserting no `Set*` call for it exists
- [ ] TTL and jitter reviewed against §4.1/§7's stale-if-error hard cap

### Event Consumption (§5)
*Complete only when `internal/adapter/inbound/consumer/` or `internal/usecase/invalidate.go` changed.*

- [ ] Idempotency preserved — handler failure does not falsely mark the event processed (see `EvictProcessed`)
- [ ] One eviction test added asserting the exact key touched and nothing else
- [ ] `scripts/init-localstack.sh` and the CI `test` job's queue list updated if a new queue was added

### Security
- [ ] No new source of identity/authz input other than Envoy's validated `Attributes.MetadataContext` (§8) — never a request header
- [ ] Client-supplied headers still cannot influence the six output headers
- [ ] Only `sub`/`iss` are logged — no raw claim (e.g. `auth_time`) added to any log call

### Documentation
- [ ] README updated (if the `Check` interface, env vars, or event table changed)
- [ ] ARCHITECTURE.md updated (if layering, flows, or key invariants changed)
- [ ] `CHANGELOG.md` `[Unreleased]` section updated

---

## Related Issue
Closes #<issue-id>

---

## Deployment Notes
Mention anything important for operators upgrading (new required env vars, config changes, breaking event contract changes, coordinated deploy order with the publishing service).
