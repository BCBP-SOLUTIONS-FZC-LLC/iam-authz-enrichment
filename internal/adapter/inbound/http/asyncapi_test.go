package http

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	apispec "github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/api"
)

// ── parseAsyncSpec ────────────────────────────────────────────────────────────

func TestParseAsyncSpec_HappyPath(t *testing.T) {
	s, err := parseAsyncSpec([]byte("asyncapi: '3.0.0'\ninfo:\n  title: t\n  version: v\n"))
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.Equal(t, "3.0.0", s.AsyncAPI)
	assert.Equal(t, "t", s.Info.Title)
}

func TestParseAsyncSpec_InvalidYAML_ReturnsError(t *testing.T) {
	_, err := parseAsyncSpec([]byte("\t\tnot: valid\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse AsyncAPI spec")
}

// TestLoadAsyncSpec_RealEmbeddedSpec exercises the actual embedded
// api/asyncapi.yaml (via loadAsyncSpec, which sync.Once-wraps this same
// parse) end to end — this service is receive-only, so all 15 event types
// must come back tagged consumed, and there must be zero published
// messages.
func TestLoadAsyncSpec_RealEmbeddedSpec_AllMessagesConsumed(t *testing.T) {
	spec, err := loadAsyncSpec()
	require.NoError(t, err)
	require.NotNil(t, spec)

	pub, con := splitMessagesByDirection(spec.Comps.Messages)
	assert.Empty(t, pub, "this service publishes zero events")
	assert.Len(t, con, 15)
	assert.Contains(t, con, "MembershipRevoked")
	assert.Contains(t, con, "UserDeleted")
	assert.Contains(t, con, "TenderRestricted")
}

// ── asyncMessage.isConsumed / splitMessagesByDirection ────────────────────────

func TestIsConsumed_NoTags_ReturnsFalse(t *testing.T) {
	msg := &asyncMessage{}
	assert.False(t, msg.isConsumed())
}

func TestIsConsumed_PublishedTag_ReturnsFalse(t *testing.T) {
	msg := &asyncMessage{Tags: []asyncRef{{Ref: "#/components/tags/published"}}}
	assert.False(t, msg.isConsumed())
}

func TestIsConsumed_ConsumedTag_ReturnsTrue(t *testing.T) {
	msg := &asyncMessage{Tags: []asyncRef{{Ref: "#/components/tags/consumed"}}}
	assert.True(t, msg.isConsumed())
}

func TestSplitMessagesByDirection_AllConsumed_PublishedEmpty(t *testing.T) {
	pub, con := splitMessagesByDirection(map[string]asyncMessage{
		"TenderRestricted": {Tags: []asyncRef{{Ref: "#/components/tags/consumed"}}},
		"UserDeleted":      {Tags: []asyncRef{{Ref: "#/components/tags/consumed"}}},
	})
	assert.Empty(t, pub)
	assert.Equal(t, []string{"TenderRestricted", "UserDeleted"}, con)
}

func TestSplitMessagesByDirection_AllPublished_ConsumedEmpty(t *testing.T) {
	pub, con := splitMessagesByDirection(map[string]asyncMessage{
		"EventA": {Tags: []asyncRef{{Ref: "#/components/tags/published"}}},
		"EventB": {Tags: []asyncRef{{Ref: "#/components/tags/published"}}},
	})
	assert.ElementsMatch(t, []string{"EventA", "EventB"}, pub)
	assert.Empty(t, con)
}

func TestSplitMessagesByDirection_Mixed_SplitsCorrectly(t *testing.T) {
	pub, con := splitMessagesByDirection(map[string]asyncMessage{
		"Published": {Tags: []asyncRef{{Ref: "#/components/tags/published"}}},
		"Consumed":  {Tags: []asyncRef{{Ref: "#/components/tags/consumed"}}},
	})
	assert.Equal(t, []string{"Published"}, pub)
	assert.Equal(t, []string{"Consumed"}, con)
}

// ── renderMessage ─────────────────────────────────────────────────────────────

func TestRenderMessage_ConsumedTag_RendersReceiveBadge(t *testing.T) {
	var buf bytes.Buffer
	msg := &asyncMessage{
		Title: "Tender Restricted",
		Tags:  []asyncRef{{Ref: "#/components/tags/consumed"}},
	}
	renderMessage(&buf, "TenderRestricted", msg, &asyncComponents{})
	out := buf.String()
	assert.Contains(t, out, `class="badge m-recv">RECEIVE`)
	assert.NotContains(t, out, `class="badge m-send">SEND`)
}

func TestRenderMessage_EmptyTitle_UsesName(t *testing.T) {
	var buf bytes.Buffer
	msg := &asyncMessage{Title: "", Tags: []asyncRef{{Ref: "#/components/tags/consumed"}}}
	renderMessage(&buf, "MyFallbackName", msg, &asyncComponents{Schemas: map[string]asyncSchema{}})
	assert.Contains(t, buf.String(), "MyFallbackName")
}

func TestRenderMessage_WithSNSEventType_RendersAttributeSpan(t *testing.T) {
	bindingsNode := mustParseYAML(t, `
sns:
  messageAttributes:
    EventType:
      value: OrderCreated
`)
	var buf bytes.Buffer
	msg := &asyncMessage{
		Title:    "Order Created",
		Bindings: *bindingsNode,
		Tags:     []asyncRef{{Ref: "#/components/tags/consumed"}},
	}
	renderMessage(&buf, "OrderCreated", msg, &asyncComponents{Schemas: map[string]asyncSchema{}})
	assert.Contains(t, buf.String(), "OrderCreated")
	assert.Contains(t, buf.String(), "event_type")
}

// ── renderPage: direction-section omission (this service's own shape) ────────

func TestRenderPage_NoPublishedMessages_OmitsPublishedSection(t *testing.T) {
	spec := &asyncSpec{
		Info: asyncInfo{Title: "Test", Version: "1.0"},
		Comps: asyncComponents{
			Messages: map[string]asyncMessage{
				"TenderRestricted": {Title: "Tender Restricted", Tags: []asyncRef{{Ref: "#/components/tags/consumed"}}},
			},
			Schemas: map[string]asyncSchema{},
		},
	}
	var buf bytes.Buffer
	renderPage(&buf, spec, "dev")
	out := buf.String()
	assert.NotContains(t, out, "Published Messages")
	assert.Contains(t, out, "Consumed Messages")
	assert.Contains(t, out, `id="msg-TenderRestricted"`)
}

func TestRenderPage_NoMessagesAtAll_OmitsBothSections(t *testing.T) {
	spec := &asyncSpec{
		Info:  asyncInfo{Title: "Test", Version: "1.0"},
		Comps: asyncComponents{Messages: map[string]asyncMessage{}, Schemas: map[string]asyncSchema{}},
	}
	var buf bytes.Buffer
	renderPage(&buf, spec, "dev")
	out := buf.String()
	assert.NotContains(t, out, "Published Messages")
	assert.NotContains(t, out, "Consumed Messages")
}

func TestRenderPage_PublishedMessages_RendersBothSections(t *testing.T) {
	spec := &asyncSpec{
		Info: asyncInfo{Title: "Test API", Version: "1.0"},
		Comps: asyncComponents{
			Messages: map[string]asyncMessage{
				"SomePublishedEvent": {Title: "Some Published", Tags: []asyncRef{{Ref: "#/components/tags/published"}}},
				"SomeConsumedEvent":  {Title: "Some Consumed", Tags: []asyncRef{{Ref: "#/components/tags/consumed"}}},
			},
			Schemas: map[string]asyncSchema{},
		},
	}
	var buf bytes.Buffer
	renderPage(&buf, spec, "dev")
	out := buf.String()
	assert.Contains(t, out, "Published Messages")
	assert.Contains(t, out, "Consumed Messages")
	assert.Contains(t, out, `id="msg-SomePublishedEvent"`)
	assert.Contains(t, out, `id="msg-SomeConsumedEvent"`)
}

// Same regression-class guard the underlying renderer already carries from
// iam-user-profile/iam-tender-acl: every message/schema in the map must
// render a card, not just ones a hardcoded allowlist happens to name.
func TestRenderPage_AllMessagesAndSchemasRender_RegardlessOfName(t *testing.T) {
	spec := &asyncSpec{
		Info: asyncInfo{Title: "Test", Version: "1.0"},
		Comps: asyncComponents{
			Messages: map[string]asyncMessage{
				"SomeBrandNewConsumedEvent": {Title: "Some Brand New Consumed Event", Tags: []asyncRef{{Ref: "#/components/tags/consumed"}}},
			},
			Schemas: map[string]asyncSchema{
				"SomeBrandNewSchema": {Properties: map[string]asyncProp{"id": {Type: "string"}}},
			},
		},
	}
	var buf bytes.Buffer
	renderPage(&buf, spec, "dev")
	out := buf.String()
	assert.Contains(t, out, `id="msg-SomeBrandNewConsumedEvent"`)
	assert.Contains(t, out, `id="schema-SomeBrandNewSchema"`)
}

func TestRenderPage_LongDescription_Truncated(t *testing.T) {
	spec := &asyncSpec{
		Info: asyncInfo{
			Title:   "Test API",
			Version: "1.0",
			Desc:    strings.Repeat("x", 850),
		},
		Comps: asyncComponents{Schemas: map[string]asyncSchema{}},
	}
	var buf bytes.Buffer
	renderPage(&buf, spec, "dev")
	assert.Contains(t, buf.String(), "truncated")
}

// TestRenderPage_LongDescription_MultiByteBoundary_ValidUTF8 reproduces the
// real bug: the actual api/asyncapi.yaml info.description uses box-drawing
// characters (─, U+2500, 3 bytes in UTF-8) to draw an ASCII table. A
// byte-level truncation (short[:800]) can land in the middle of one of
// these multi-byte sequences, producing invalid UTF-8 that browsers render
// as U+FFFD ("�") — exactly what was reported against the live /asyncapi
// page. This constructs a description where a 3-byte rune straddles the
// 800-byte cut point and asserts the output never contains the replacement
// character.
func TestRenderPage_LongDescription_MultiByteBoundary_ValidUTF8(t *testing.T) {
	// 799 ASCII bytes then a 3-byte rune (─) — byte offset 800 falls
	// exactly inside that rune's UTF-8 encoding.
	desc := strings.Repeat("x", 799) + "─" + strings.Repeat("y", 50)
	spec := &asyncSpec{
		Info: asyncInfo{
			Title:   "Test API",
			Version: "1.0",
			Desc:    desc,
		},
		Comps: asyncComponents{Schemas: map[string]asyncSchema{}},
	}
	var buf bytes.Buffer
	renderPage(&buf, spec, "dev")
	out := buf.String()

	assert.True(t, utf8.ValidString(out), "rendered page must be valid UTF-8")
	assert.NotContains(t, out, "�", "must never render the UTF-8 replacement character")
	assert.Contains(t, out, "truncated")
}

// TestAsyncAPIHandler_RealSpec_NeverEmitsReplacementCharacter is the
// strongest form of the regression: renders the actual embedded
// api/asyncapi.yaml (whose real info.description is well over 800 bytes and
// full of ─/— multi-byte characters) and asserts the HTML response contains
// no U+FFFD anywhere — the literal symptom reported against the live page.
func TestAsyncAPIHandler_RealSpec_NeverEmitsReplacementCharacter(t *testing.T) {
	c, w := newTestGinContext()
	c.Set(envLabelContextKey, "dev")

	AsyncAPIHandler(c)

	body := w.Body.String()
	require.True(t, utf8.ValidString(body), "rendered page must be valid UTF-8")
	assert.NotContains(t, body, "�")
}

func TestTruncateRunes_UnderLimit_ReturnsUnchanged(t *testing.T) {
	assert.Equal(t, "short", truncateRunes("short", 800, "…"))
}

func TestTruncateRunes_OverLimit_TruncatesAndAppendsSuffix(t *testing.T) {
	got := truncateRunes(strings.Repeat("x", 10), 5, "…")
	assert.Equal(t, strings.Repeat("x", 5)+"…", got)
}

func TestTruncateRunes_MultiByteBoundary_NeverSplitsARune(t *testing.T) {
	// The cut falls between the 5th and 6th rune, not mid-byte — a
	// byte-level s[:5] on this string would split the "─" (3 bytes) in half.
	s := "abcd─efgh"
	got := truncateRunes(s, 5, "")
	assert.True(t, utf8.ValidString(got))
	assert.Equal(t, "abcd─", got)
}

func TestRenderPage_ProdEnv_RendersBadge(t *testing.T) {
	spec := &asyncSpec{Info: asyncInfo{Title: "Test API", Version: "1.0"}, Comps: asyncComponents{Schemas: map[string]asyncSchema{}}}
	var buf bytes.Buffer
	renderPage(&buf, spec, "production")
	assert.Contains(t, buf.String(), "PRODUCTION")
}

func TestRenderPage_EmptyEnv_DefaultsBadge(t *testing.T) {
	spec := &asyncSpec{Info: asyncInfo{Title: "Test API", Version: "1.0"}, Comps: asyncComponents{Schemas: map[string]asyncSchema{}}}
	var buf bytes.Buffer
	renderPage(&buf, spec, "")
	assert.Contains(t, buf.String(), "DEV")
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

func newTestGinContext() (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/asyncapi", http.NoBody)
	return c, w
}

func TestAsyncAPIHandler_RealSpec_Returns200HTML(t *testing.T) {
	c, w := newTestGinContext()
	c.Set(envLabelContextKey, "dev")

	AsyncAPIHandler(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
	body := w.Body.String()
	assert.Contains(t, body, "MembershipRevoked")
	assert.Contains(t, body, "TenderRestricted")
	assert.NotContains(t, body, "Published Messages")
}

func TestAsyncAPIYAMLHandler_ReturnsEmbeddedSpecVerbatim(t *testing.T) {
	c, w := newTestGinContext()

	AsyncAPIYAMLHandler(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/yaml")
	assert.Contains(t, w.Body.String(), "asyncapi: 3.0.0")
	assert.Contains(t, w.Body.String(), "MembershipRevoked")
}

func TestEnvMiddleware_StashesEnvOnContext(t *testing.T) {
	r := gin.New()
	r.Use(envMiddleware("staging"))
	r.GET("/asyncapi", AsyncAPIHandler)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/asyncapi", http.NoBody)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "STAGING")
}

// TestAsyncAPIHandler_SpecParseError_Returns500 exercises AsyncAPIHandler's
// error branch — loadAsyncSpec failing — by temporarily swapping the
// embedded spec bytes for invalid YAML and resetting the sync.Once so the
// next loadAsyncSpec call re-parses. The real embed and the singleton are
// restored via t.Cleanup before any other test can observe the swap; every
// assignment below is a fresh value (sync.Once{} is a composite literal,
// never a copy of the existing — possibly-already-fired — package var), so
// this doesn't trip go vet's copylocks check.
func TestAsyncAPIHandler_SpecParseError_Returns500(t *testing.T) {
	origSpec := apispec.AsyncAPISpec
	t.Cleanup(func() {
		apispec.AsyncAPISpec = origSpec
		asyncSpecOnce = sync.Once{}
		asyncSpecVal = nil
		asyncSpecErr = nil
	})
	apispec.AsyncAPISpec = []byte("\t\tnot: valid\n")
	asyncSpecOnce = sync.Once{}
	asyncSpecVal = nil
	asyncSpecErr = nil

	c, w := newTestGinContext()
	AsyncAPIHandler(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "internal_server_error")
}

func TestWriteError_WritesJSONErrorBody(t *testing.T) {
	c, w := newTestGinContext()
	writeError(c, http.StatusInternalServerError, "internal_server_error")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "internal_server_error")
}

func TestEnvLabelFromGin_NonStringValue_ReturnsEmpty(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	// Set the context key to a non-string value → type assertion fails → returns ""
	c.Set(envLabelContextKey, 12345)
	assert.Equal(t, "", envLabelFromGin(c))
}

// ── router wiring (DocsConfig / registerDocsRoutes / docsAuthMiddleware) ──────

func TestRegisterDocsRoutes_Active_MountsAsyncAPIRoutes(t *testing.T) {
	engine := gin.New()
	registerDocsRoutes(engine, DocsConfig{Environment: "development"})

	for _, path := range []string{"/asyncapi", "/asyncapi.yaml"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, http.NoBody)
		engine.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "path=%s", path)
	}
}

func TestRegisterDocsRoutes_Inactive_AsyncAPIRoutesAbsent(t *testing.T) {
	engine := gin.New()
	registerDocsRoutes(engine, DocsConfig{Environment: "production", Enabled: false})

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/asyncapi", http.NoBody)
	engine.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRegisterDocsRoutes_ProductionWithToken_RequiresBearerToken(t *testing.T) {
	engine := gin.New()
	registerDocsRoutes(engine, DocsConfig{Environment: "production", Enabled: true, AuthToken: "secret"})

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/asyncapi", http.NoBody)
	engine.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/asyncapi", http.NoBody)
	req2.Header.Set("Authorization", "Bearer secret")
	engine.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
}

// ── walkYAML ──────────────────────────────────────────────────────────────────

func TestWalkYAML_NilNode_ReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", walkYAML(nil, "key"))
}

func TestWalkYAML_EmptyKeys_ReturnsEmpty(t *testing.T) {
	node := &yaml.Node{Kind: yaml.MappingNode}
	assert.Equal(t, "", walkYAML(node))
}

func TestWalkYAML_DocumentNode_UnwrapsAndFinds(t *testing.T) {
	inner := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "foo"},
			{Kind: yaml.ScalarNode, Value: "bar"},
		},
	}
	doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{inner}}
	assert.Equal(t, "bar", walkYAML(doc, "foo"))
}

func TestWalkYAML_MappingNode_KeyFound_ReturnsValue(t *testing.T) {
	node := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "mykey"},
			{Kind: yaml.ScalarNode, Value: "myval"},
		},
	}
	assert.Equal(t, "myval", walkYAML(node, "mykey"))
}

func TestWalkYAML_MappingNode_KeyNotFound_ReturnsEmpty(t *testing.T) {
	node := &yaml.Node{
		Kind:    yaml.MappingNode,
		Content: []*yaml.Node{},
	}
	assert.Equal(t, "", walkYAML(node, "missing"))
}

func TestWalkYAML_NestedPath_ReturnsDeepValue(t *testing.T) {
	child := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "value"},
			{Kind: yaml.ScalarNode, Value: "deep"},
		},
	}
	root := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "parent"},
			child,
		},
	}
	assert.Equal(t, "deep", walkYAML(root, "parent", "value"))
}

// ── snsEventType ──────────────────────────────────────────────────────────────

func TestSnsEventType_NilNode_ReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", snsEventType(nil))
}

func TestSnsEventType_ZeroKindNode_ReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", snsEventType(&yaml.Node{Kind: 0}))
}

func TestSnsEventType_EventTypeCamelCase_ReturnsValue(t *testing.T) {
	node := mustParseYAML(t, `
sns:
  messageAttributes:
    EventType:
      value: MyEvent
`)
	assert.Equal(t, "MyEvent", snsEventType(node))
}

func TestSnsEventType_EventTypeSnakeCase_ReturnsValue(t *testing.T) {
	node := mustParseYAML(t, `
sns:
  messageAttributes:
    event_type:
      value: my_event
`)
	assert.Equal(t, "my_event", snsEventType(node))
}

func mustParseYAML(t *testing.T, src string) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &doc))
	return &doc
}

// ── propType ──────────────────────────────────────────────────────────────────

func TestPropType_Ref_ReturnsSchemaName(t *testing.T) {
	p := &asyncProp{Ref: "#/components/schemas/MyType"}
	assert.Equal(t, "MyType", propType(p))
}

func TestPropType_Format_IncludesFormat(t *testing.T) {
	p := &asyncProp{Type: "string", Format: "uuid"}
	assert.Equal(t, "string(uuid)", propType(p))
}

func TestPropType_ArrayWithItemType_ReturnsArrayType(t *testing.T) {
	p := &asyncProp{Type: "array", Items: &asyncProp{Type: "string"}}
	assert.Equal(t, "array<string>", propType(p))
}

func TestPropType_ArrayWithItemRef_ReturnsArrayRef(t *testing.T) {
	p := &asyncProp{Type: "array", Items: &asyncProp{Ref: "#/components/schemas/Entry"}}
	assert.Equal(t, "array<Entry>", propType(p))
}

func TestPropType_PlainType_ReturnsType(t *testing.T) {
	p := &asyncProp{Type: "boolean"}
	assert.Equal(t, "boolean", propType(p))
}

// ── typeHTML ──────────────────────────────────────────────────────────────────

func TestTypeHTML_Ref_RendersSchemaLink(t *testing.T) {
	p := &asyncProp{Ref: "#/components/schemas/MySchema"}
	out := typeHTML(p)
	assert.Contains(t, out, `href="#schema-MySchema"`)
	assert.Contains(t, out, "MySchema")
}

func TestTypeHTML_ArrayWithRef_RendersArrayLink(t *testing.T) {
	p := &asyncProp{Type: "array", Items: &asyncProp{Ref: "#/components/schemas/Item"}}
	out := typeHTML(p)
	assert.Contains(t, out, "array")
	assert.Contains(t, out, `href="#schema-Item"`)
}

func TestTypeHTML_Fallback_RendersPropType(t *testing.T) {
	p := &asyncProp{Type: "integer"}
	out := typeHTML(p)
	assert.Contains(t, out, "integer")
	assert.Contains(t, out, `class="prop-type"`)
}

// ── resolveSchema ─────────────────────────────────────────────────────────────

func TestResolveSchema_Direct_NoAllOfNoRef_ReturnsSelf(t *testing.T) {
	sc := &asyncSchema{Properties: map[string]asyncProp{"id": {Type: "string"}}}
	comps := &asyncComponents{Schemas: map[string]asyncSchema{}}
	result := resolveSchema(sc, comps)
	assert.Same(t, sc, result)
}

func TestResolveSchema_Ref_Found_ReturnsReferenced(t *testing.T) {
	comps := &asyncComponents{
		Schemas: map[string]asyncSchema{
			"MyRef": {Properties: map[string]asyncProp{"name": {Type: "string"}}},
		},
	}
	sc := &asyncSchema{Ref: "#/components/schemas/MyRef"}
	result := resolveSchema(sc, comps)
	_, ok := result.Properties["name"]
	assert.True(t, ok)
}

func TestResolveSchema_Ref_NotFound_ReturnsSelf(t *testing.T) {
	comps := &asyncComponents{Schemas: map[string]asyncSchema{}}
	sc := &asyncSchema{Ref: "#/components/schemas/Missing"}
	result := resolveSchema(sc, comps)
	assert.Same(t, sc, result)
}

func TestResolveSchema_AllOf_MergesProperties(t *testing.T) {
	comps := &asyncComponents{Schemas: map[string]asyncSchema{}}
	sc := &asyncSchema{
		AllOf: []asyncSchema{
			{Properties: map[string]asyncProp{"a": {Type: "string"}}, Required: []string{"a"}},
			{Properties: map[string]asyncProp{"b": {Type: "integer"}}},
		},
	}
	result := resolveSchema(sc, comps)
	_, hasA := result.Properties["a"]
	_, hasB := result.Properties["b"]
	assert.True(t, hasA)
	assert.True(t, hasB)
	assert.Contains(t, result.Required, "a")
}

func TestResolveSchema_AllOf_DuplicatePropertyOrder_Deduped(t *testing.T) {
	comps := &asyncComponents{Schemas: map[string]asyncSchema{}}
	sc := &asyncSchema{
		AllOf: []asyncSchema{
			{
				Properties:    map[string]asyncProp{"shared": {Type: "string"}, "a": {Type: "integer"}},
				PropertyOrder: []string{"shared", "a"},
			},
			{
				Properties:    map[string]asyncProp{"shared": {Type: "string"}, "b": {Type: "boolean"}},
				PropertyOrder: []string{"shared", "b"},
			},
		},
	}
	result := resolveSchema(sc, comps)
	// "shared" appears in both — must appear only once in merged PropertyOrder
	count := 0
	for _, k := range result.PropertyOrder {
		if k == "shared" {
			count++
		}
	}
	assert.Equal(t, 1, count, "duplicate key must be deduped in merged PropertyOrder")
}

// ── renderPropsTable ──────────────────────────────────────────────────────────

func TestRenderPropsTable_NilSchema_WritesNoPropsMessage(t *testing.T) {
	var buf bytes.Buffer
	renderPropsTable(&buf, nil, "test")
	assert.Contains(t, buf.String(), "No properties")
}

func TestRenderPropsTable_EmptyProperties_WritesNoPropsMessage(t *testing.T) {
	var buf bytes.Buffer
	renderPropsTable(&buf, &asyncSchema{Properties: map[string]asyncProp{}}, "test")
	assert.Contains(t, buf.String(), "No properties")
}

func TestRenderPropsTable_WithEnum_RendersEnumValues(t *testing.T) {
	var buf bytes.Buffer
	sc := &asyncSchema{
		Properties: map[string]asyncProp{
			"status": {Type: "string", Enum: []string{"active", "suspended"}},
		},
	}
	renderPropsTable(&buf, sc, "test")
	out := buf.String()
	assert.Contains(t, out, "active")
	assert.Contains(t, out, "suspended")
}

func TestRenderPropsTable_WithItemEnum_RendersItemEnumValues(t *testing.T) {
	var buf bytes.Buffer
	sc := &asyncSchema{
		Properties: map[string]asyncProp{
			"roles": {Type: "array", Items: &asyncProp{Enum: []string{"admin", "member"}}},
		},
	}
	renderPropsTable(&buf, sc, "test")
	out := buf.String()
	assert.Contains(t, out, "admin")
	assert.Contains(t, out, "member")
}

func TestRenderPropsTable_WithExample_RendersExampleBlock(t *testing.T) {
	var buf bytes.Buffer
	sc := &asyncSchema{
		Properties: map[string]asyncProp{
			"id": {Type: "string", Example: "some-uuid"},
		},
	}
	renderPropsTable(&buf, sc, "test")
	assert.Contains(t, buf.String(), "some-uuid")
}

func TestRenderPropsTable_LongDescription_Truncated(t *testing.T) {
	var buf bytes.Buffer
	sc := &asyncSchema{
		Properties: map[string]asyncProp{
			"note": {Type: "string", Desc: strings.Repeat("x", 250)},
		},
	}
	renderPropsTable(&buf, sc, "test")
	out := buf.String()
	assert.Contains(t, out, "…")
	assert.NotContains(t, out, strings.Repeat("x", 250))
}

func TestRenderPropsTable_PropertyNotInOrder_StillRendered(t *testing.T) {
	var buf bytes.Buffer
	sc := &asyncSchema{
		// PropertyOrder omits "extra" — the guard must catch it and append
		PropertyOrder: []string{"name"},
		Properties: map[string]asyncProp{
			"name":  {Type: "string"},
			"extra": {Type: "integer"},
		},
	}
	renderPropsTable(&buf, sc, "test")
	out := buf.String()
	assert.Contains(t, out, "name")
	assert.Contains(t, out, "extra")
}

// ── UnmarshalYAML decode error ────────────────────────────────────────────────

func TestUnmarshalYAML_DecodeError_ReturnsError(t *testing.T) {
	// A SequenceNode (not a MappingNode) will fail to decode into asyncSchema struct.
	node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	var sc asyncSchema
	err := sc.UnmarshalYAML(node)
	require.Error(t, err)
}
