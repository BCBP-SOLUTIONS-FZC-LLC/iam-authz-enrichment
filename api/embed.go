// Package api embeds this service's machine-readable event contract so the
// running binary can serve it (GET /asyncapi, GET /asyncapi.yaml — see
// internal/adapter/inbound/http/asyncapi.go) without depending on the
// source tree being present at runtime. Dockerfile's final stage copies
// only the compiled binary into the distroless image, not the repo, so a
// disk-read-relative-path approach would 404/500 in that image; embedding
// avoids the problem entirely and needs no Dockerfile change.
package api

import _ "embed"

// AsyncAPISpec is the verbatim contents of asyncapi.yaml, embedded at
// compile time.
//
//go:embed asyncapi.yaml
var AsyncAPISpec []byte
