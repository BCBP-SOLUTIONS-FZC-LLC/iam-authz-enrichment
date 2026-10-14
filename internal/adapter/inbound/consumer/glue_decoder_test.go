package consumer

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2/pkg/events"
)

// glueFrame builds the Glue wire format producers emit:
// [0x03][0x00][16-byte schema version UUID] + JSON.
func glueFrame(t *testing.T, payload string) []byte {
	t.Helper()
	id := uuid.New()
	return append(append([]byte{0x03, 0x00}, id[:]...), payload...)
}

func TestGlueDecodeCodec_StripsHeader(t *testing.T) {
	got, err := events.GlueDecodeCodec{}.Decode(context.Background(), uuid.NewString(), glueFrame(t, `{"user_id":"u1"}`))
	require.NoError(t, err)
	assert.JSONEq(t, `{"user_id":"u1"}`, string(got))
}

func TestGlueDecodeCodec_RejectsMalformedHeaders(t *testing.T) {
	for name, in := range map[string][]byte{
		"too short":         {0x03, 0x00, 0x01},
		"wrong version":     append([]byte{0x04, 0x00}, make([]byte, 16)...),
		"compressed (0x05)": append([]byte{0x03, 0x05}, make([]byte, 16)...),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := events.GlueDecodeCodec{}.Decode(context.Background(), "", in)
			assert.Error(t, err)
		})
	}
}

func TestGlueDecodeCodec_RejectsNonJSONPayload(t *testing.T) {
	// platform-events v1.6.1 GlueDecodeCodec adds a JSON-validity check that
	// the hand-rolled GlueDecoder did not have — Avro-format or binary payloads
	// behind a valid Glue header are rejected rather than forwarded to handlers
	// as unparseable bytes.
	_, err := events.GlueDecodeCodec{}.Decode(context.Background(), "", glueFrame(t, `not-json`))
	assert.Error(t, err)
}

func TestGlueDecodeCodec_EncodeAlwaysFails(t *testing.T) {
	_, _, err := events.GlueDecodeCodec{}.Encode(context.Background(), "UserUpdated", json.RawMessage(`{}`))
	assert.Error(t, err)
}

// The regression this fixes: a Glue-framed payload reaching a handler
// unstripped (the old events.NoopCodec) cannot be decoded at all.
func TestGlueDecodeCodec_FramedPayloadIsUndecodableWithoutIt(t *testing.T) {
	framed := glueFrame(t, `{"user_id":"u1"}`)
	var p struct {
		UserID string `json:"user_id"`
	}
	require.Error(t, json.Unmarshal(framed, &p), "precondition: raw Glue frame is not JSON")
	stripped, err := events.GlueDecodeCodec{}.Decode(context.Background(), "", framed)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(stripped, &p))
	assert.Equal(t, "u1", p.UserID)
}

// DeadLetterHandler only observes: it logs and returns an error so
// platform-events never deletes the message itself.
func TestDeadLetterHandler_LogsAndNeverAcks(t *testing.T) {
	log := &recordingLogger{}
	err := DeadLetterHandler("membership-authz-q", log)(context.Background(), events.Envelope[json.RawMessage]{ID: "e1", Type: "UserUpdated"})
	require.Error(t, err)
	assert.Len(t, log.errors, 1)
}

func TestQueueName(t *testing.T) {
	assert.Equal(t, "user-authz-q", queueName("http://sqs.local/000000000000/user-authz-q"))
	assert.Equal(t, "user-authz-q", queueName("http://sqs.local/000000000000/user-authz-q/"))
	assert.Equal(t, "bare", queueName("bare"))
}
