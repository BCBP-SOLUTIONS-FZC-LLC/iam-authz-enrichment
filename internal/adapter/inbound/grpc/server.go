// Package grpc is the primary inbound adapter: Envoy's ext_authz v3 gRPC
// interface (envoy.service.auth.v3.Authorization). This service is the
// Policy Decision Point; Envoy is the Policy Enforcement Point (§2 point 1).
package grpc

import (
	"context"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
)

// Server implements authv3.AuthorizationServer over a *usecase.Checker. It
// holds no state of its own beyond wire<->domain translation — all
// business logic lives in the usecase layer.
type Server struct {
	authv3.UnimplementedAuthorizationServer
	checker *usecase.Checker
	jwt     JWTMetadata
}

// NewServer builds a Server.
func NewServer(checker *usecase.Checker, jwt JWTMetadata) *Server {
	return &Server{checker: checker, jwt: jwt}
}

// Check implements authv3.AuthorizationServer. It translates the wire
// CheckRequest into usecase.CheckInput, delegates the full §3.1 precedence
// chain to Checker.Check, and translates the resulting domain.Decision back
// to a CheckResponse. It never reads req.Attributes.Request.Http.Headers for
// identity or policy facts — see claims.go/requestfacts.go for why, and
// §8.2's header-spoofing invariant for why that matters.
func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	// A missing verified subject is still handed to Checker.Check, which
	// denies it as DENY_MALFORMED_IDENTITY first thing — so that deny is
	// timed and counted in iam_authz_enrichment_decisions_total like every
	// other decision, instead of returning from here unrecorded.
	decision := s.checker.Check(ctx, usecase.CheckInput{
		Claims:  decodeClaims(req, s.jwt),
		Request: decodeRequestFacts(req),
	})

	if decision.Allow {
		return okResponse(decision.Headers), nil
	}
	return deniedResponse(decision.Reason), nil
}
