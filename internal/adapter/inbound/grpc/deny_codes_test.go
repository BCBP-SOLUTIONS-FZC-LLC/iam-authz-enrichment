package grpc

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
)

type denyCodesFile struct {
	Comment          string `json:"$comment"`
	ContentType      string `json:"contentType"`
	RetryAfterHeader bool   `json:"retryAfterHeader"`
	Codes            []struct {
		ErrorCode string `json:"errorCode"`
		Status    int    `json:"status"`
		Type      string `json:"type"`
		Title     string `json:"title"`
		Detail    string `json:"detail"`
		Retryable bool   `json:"retryable"`
		Action    string `json:"action"`
		Meaning   string `json:"meaning"`
	} `json:"codes"`
}

// denyCodeActions is the client action each reason's usual cause calls for.
// Only the 503 is retryable unchanged; DENY_MFA_STALE is retried after a
// step-up. DENY_MALFORMED_IDENTITY is "none", not a sign-in: most of its
// causes are route or config faults a new token cannot fix, and a sign-in
// action would loop.
var denyCodeActions = map[domain.DenyReason]string{
	domain.DenyMFAStale:           "step_up",
	domain.DenyServiceUnavailable: "retry_with_backoff",
}

// api/deny-codes.json is the list the frontend repos pin by release tag
// (web-shell AZ-3); the binary does not serve it. It must list exactly
// domain.DenyReasons(), in order, and every field must match what
// deniedResponse actually sends for that reason.
func TestDenyCodesJSON_MatchesDenyReasons(t *testing.T) {
	t.Parallel()
	var f denyCodesFile
	raw, err := os.ReadFile("../../../../api/deny-codes.json")
	require.NoError(t, err)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&f))

	assert.Equal(t, "application/problem+json", f.ContentType)
	assert.False(t, f.RetryAfterHeader, "no deny sets Retry-After")

	reasons := domain.DenyReasons()
	require.Len(t, f.Codes, len(reasons), "deny-codes.json must list every DenyReason, and nothing else")
	for i, reason := range reasons {
		c := f.Codes[i]
		t.Run(string(reason), func(t *testing.T) {
			resp := deniedResponse(reason, &authv3.CheckRequest{}, "")
			denied := resp.GetDeniedResponse()
			for _, h := range denied.GetHeaders() {
				if strings.EqualFold(h.GetHeader().GetKey(), "retry-after") {
					t.Fatalf("%s sets Retry-After", reason)
				}
			}
			var body map[string]any
			require.NoError(t, json.Unmarshal([]byte(denied.GetBody()), &body))

			assert.Equal(t, string(reason), c.ErrorCode)
			assert.Equal(t, reason.HTTPStatus(), c.Status)
			assert.Equal(t, body["type"], c.Type)
			assert.Equal(t, body["title"], c.Title)
			assert.Equal(t, body["detail"], c.Detail)
			assert.Equal(t, reason.HTTPStatus() == 503, c.Retryable, "only the 503 is retryable unchanged")
			want := denyCodeActions[reason]
			if want == "" {
				want = "none"
			}
			assert.Equal(t, want, c.Action)
			assert.NotEmpty(t, c.Meaning)
		})
	}
}
