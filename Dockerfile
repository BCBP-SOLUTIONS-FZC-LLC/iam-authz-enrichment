# Pin base images to SHA digests for reproducible, supply-chain-safe builds.
# Update with: make pin-base-images  (requires docker and network access)
# Current digests are tracked in .docker-digests; CI enforces they match this file.
FROM golang:1.26.9-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS builder

WORKDIR /build

# GOPRIVATE is a Go toolchain module-privacy setting (an import-path glob
# pattern), not a credential — hadolint's DL3064 heuristic flags it purely
# because the name contains "PRIVATE". The ignore directive must be the
# line immediately before the instruction it applies to.
# hadolint ignore=DL3064
ENV GOPRIVATE="github.com/BCBP-SOLUTIONS-FZC-LLC/*"
ENV GONOSUMDB="github.com/BCBP-SOLUTIONS-FZC-LLC/*"

# hadolint ignore=DL3018
RUN apk add --no-cache git

ARG BUILD_VERSION=dev
ARG SOURCE_DATE_EPOCH=0

COPY go.mod go.sum ./

RUN --mount=type=secret,id=go_private_token \
    TOKEN=$(cat /run/secrets/go_private_token 2>/dev/null || true) && \
    if [ -z "$TOKEN" ]; then echo "ERROR: go_private_token secret is missing or empty — pass --secret id=go_private_token,src=<token-file>"; exit 1; fi && \
    git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/" && \
    go mod download && \
    git config --global --unset url."https://x-access-token:${TOKEN}@github.com/".insteadOf

COPY --link . .

RUN CGO_ENABLED=0 GOOS=linux \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    go build -trimpath \
    -ldflags="-s -w -X main.buildVersion=${BUILD_VERSION}" \
    -o bin/iam-authz-enrichment ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG BUILD_VERSION=dev
ENV BUILD_VERSION=${BUILD_VERSION}

LABEL org.opencontainers.image.title="iam-authz-enrichment" \
      org.opencontainers.image.source="https://github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment" \
      org.opencontainers.image.vendor="BCBP Solutions FZC LLC" \
      org.opencontainers.image.revision="${BUILD_VERSION}"

COPY --from=builder /build/bin/iam-authz-enrichment /iam-authz-enrichment

EXPOSE 8080 9090 9091

ENTRYPOINT ["/iam-authz-enrichment"]
