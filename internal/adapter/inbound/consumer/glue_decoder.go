package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2/pkg/events"
)

// glueHeaderLen is the AWS Glue Schema Registry wire-format header:
// [0x03 header version][0x00 compression = none][16-byte schema-version UUID].
const glueHeaderLen = 18

// GlueDecoder is a decode-only events.Codec that strips the Glue wire-format
// header every sibling producer (iam-org-membership, iam-user-profile,
// iam-realm-provisioner, iam-tender-acl, …) prepends to `data` once its own
// Glue registry is configured. The header is self-describing, so decoding
// needs no Glue client, registry name or IAM permission — only producers
// ever call Glue.
//
// platform-events invokes the consumer codec only for an envelope whose
// `dataschema` (SchemaID) is set, i.e. exactly the Glue-encoded ones; a
// plain-JSON envelope never reaches Decode. Without this codec (the
// previous events.NoopCodec) the framed bytes reached every handler
// unstripped, json.Unmarshal failed on every Glue-encoded event, and each
// one dead-lettered after maxReceiveCount deliveries with its cache
// eviction never applied — for TenderRestricted (ae:restricted has no TTL)
// indefinitely.
type GlueDecoder struct{}

var _ events.Codec = GlueDecoder{}

// Decode strips the 18-byte Glue header and returns the JSON payload.
func (GlueDecoder) Decode(_ context.Context, _ string, encoded []byte) (json.RawMessage, error) {
	if len(encoded) < glueHeaderLen {
		return nil, fmt.Errorf("glue decode: payload is %d bytes, shorter than the %d-byte header", len(encoded), glueHeaderLen)
	}
	if encoded[0] != 0x03 {
		return nil, fmt.Errorf("glue decode: unsupported header version 0x%02x (want 0x03)", encoded[0])
	}
	if encoded[1] != 0x00 {
		return nil, fmt.Errorf("glue decode: unsupported compression 0x%02x (want 0x00, none)", encoded[1])
	}
	return json.RawMessage(encoded[glueHeaderLen:]), nil
}

// Encode always fails — this service never publishes (HLD §5.4 / EVT-2).
func (GlueDecoder) Encode(context.Context, string, json.RawMessage) ([]byte, string, error) {
	return nil, "", errors.New("glue decoder: decode-only, this service never publishes")
}
