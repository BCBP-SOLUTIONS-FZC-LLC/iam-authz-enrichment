# Pin base images to SHA digests for reproducible, supply-chain-safe builds.
# Update with: make pin-base-images  (requires docker and network access)
# Current digests are tracked in .docker-digests; CI enforces they match this file.
FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

WORKDIR /build

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

FROM gcr.io/distroless/static-debian12:nonroot@sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a

ARG BUILD_VERSION=dev
ENV BUILD_VERSION=${BUILD_VERSION}

LABEL org.opencontainers.image.title="iam-authz-enrichment" \
      org.opencontainers.image.source="https://github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment" \
      org.opencontainers.image.vendor="BCBP Solutions FZC LLC" \
      org.opencontainers.image.revision="${BUILD_VERSION}"

COPY --from=builder /build/bin/iam-authz-enrichment /iam-authz-enrichment

EXPOSE 8080 9091

ENTRYPOINT ["/iam-authz-enrichment"]
