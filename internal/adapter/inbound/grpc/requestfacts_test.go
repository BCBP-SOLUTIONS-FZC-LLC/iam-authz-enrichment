package grpc

import (
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
)

func TestTenderIDFromPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		path string
		want string
	}{
		{"simple resource path", "/api/v1/tenders/tender-1", "tender-1"},
		{"nested sub-resource path, any method", "/api/v1/tenders/tender-1/sections/3", "tender-1"},
		{"query string stripped before parsing", "/api/v1/tenders/tender-1?expand=sections", "tender-1"},
		{"trailing slash yields empty id", "/api/v1/tenders/", ""},
		{"no /tenders/ segment at all", "/api/v1/users/alice", ""},
		{"empty path", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tenderIDFromPath(tc.path))
		})
	}
}

func TestDecodeRequestFacts_TenderIDFromPath_NotContextExtensions(t *testing.T) {
	t.Parallel()
	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "PATCH",
					Path:   "/api/v1/tenders/tender-1/sections/3",
				},
			},
			// A stale/forged tender_id here must never override the path —
			// context_extensions no longer carries this key at all.
			ContextExtensions: map[string]string{
				"tender_id":             "some-other-tender",
				"required_access_level": "edit",
			},
		},
	}

	facts := decodeRequestFacts(req)

	assert.Equal(t, "tender-1", facts.TenderID)
	assert.Equal(t, "edit", facts.RequiredAccessLevel)
}

func TestDecodeRequestFacts_NoTenderPath(t *testing.T) {
	t.Parallel()
	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{Method: "GET", Path: "/api/v1/departments"},
			},
		},
	}

	facts := decodeRequestFacts(req)

	assert.Empty(t, facts.TenderID)
}
