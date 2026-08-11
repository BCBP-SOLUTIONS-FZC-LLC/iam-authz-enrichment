// Package grpc is the primary inbound adapter: Envoy's ext_authz v3 gRPC
// interface (envoy.service.auth.v3.Authorization). This service is the
// Policy Decision Point; Envoy is the Policy Enforcement Point (§2 point 1).
package grpc

import (
	"context"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
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
	claims := decodeClaims(req, s.jwt)
	if claims.Subject == "" {
		// §8.1: no other claim or header is a valid identity input. A
		// request with no verified subject at all has nothing this service
		// can authorize against.
		return deniedResponse(domain.DenyMalformedIdentity), nil
	}

	decision := s.checker.Check(ctx, usecase.CheckInput{
		Claims:  claims,
		Request: decodeRequestFacts(req),
	})

	if decision.Allow {
		return okResponse(decision.Headers), nil
	}
	return deniedResponse(decision.Reason), nil
}
