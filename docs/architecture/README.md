# Architecture diagrams

Standalone Mermaid source files for `ARCHITECTURE.md`. Each `.mmd` file is embedded as a fenced code block in the parent document with a `> Source:` back-reference.

| File | Diagram | Embedded in |
|------|---------|------------|
| [`layer-model.mmd`](mermaid/layer-model.mmd) | Clean Architecture layer graph | ARCHITECTURE.md §Layer model |
| [`package-dependencies.mmd`](mermaid/package-dependencies.mmd) | Go import graph (mirrors `.go-arch-lint.yml`) | ARCHITECTURE.md §Package dependency graph |
| [`request-flow.mmd`](mermaid/request-flow.mmd) | Full `Check()` precedence chain (§3.1) | ARCHITECTURE.md §Request flow |
| [`cache-strategy.mmd`](mermaid/cache-strategy.mmd) | Cache keys, TTLs, read-through path, eviction rules | ARCHITECTURE.md §Cache strategy |
| [`event-flow.mmd`](mermaid/event-flow.mmd) | SQS consumer → dedup → Invalidator → cache | ARCHITECTURE.md §Event flow |
| [`failure-handling.mmd`](mermaid/failure-handling.mmd) | §7 failure-handling matrix as a decision flow | ARCHITECTURE.md §Failure handling |
| [`observability-stack.mmd`](mermaid/observability-stack.mmd) | Interceptors, OTel spans, Prometheus, log redaction | ARCHITECTURE.md §Observability stack |

To render locally, open any `.mmd` file in a Mermaid-aware IDE (VS Code + Mermaid Preview, IntelliJ + Mermaid plugin) or paste into [mermaid.live](https://mermaid.live). GitHub renders the fenced blocks in `ARCHITECTURE.md` natively.
