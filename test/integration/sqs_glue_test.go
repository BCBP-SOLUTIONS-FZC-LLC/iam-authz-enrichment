//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/v2/pkg/events"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/inbound/consumer"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/test/fixtures"
)

// newRedriveQueue creates a uniquely named queue + DLQ with production's
// RedrivePolicy (maxReceiveCount=5), so these tests are self-contained on
// any running SQS emulator (floci / LocalStack) and never touch the shared
// membership-authz-q. Skips if no emulator is reachable.
func newRedriveQueue(t *testing.T, client *sqs.Client) (queueURL, dlqURL string) {
	t.Helper()
	ctx := context.Background()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	dlq, err := client.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: awssdk.String("it-authz-dlq-" + suffix)})
	if err != nil {
		t.Skipf("skipping — no SQS emulator at %s (%v)", endpointURL(), err)
	}
	attrs, err := client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: dlq.QueueUrl,
		AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
	require.NoError(t, err)
	q, err := client.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: awssdk.String("it-authz-q-" + suffix), Attributes: map[string]string{
		"RedrivePolicy": `{"deadLetterTargetArn":"` + attrs.Attributes["QueueArn"] + `","maxReceiveCount":"5"}`,
	}})
	require.NoError(t, err)
	return *q.QueueUrl, *dlq.QueueUrl
}

func approxDepth(t *testing.T, client *sqs.Client, url string) string {
	out, err := client.GetQueueAttributes(context.Background(), &sqs.GetQueueAttributesInput{QueueUrl: awssdk.String(url),
		AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameApproximateNumberOfMessages, sqstypes.QueueAttributeNameApproximateNumberOfMessagesNotVisible}})
	require.NoError(t, err)
	return out.Attributes["ApproximateNumberOfMessages"] + "/" + out.Attributes["ApproximateNumberOfMessagesNotVisible"]
}

// glueFramedEnvelope builds what a sibling producer publishes once its Glue
// registry is set: data = base64([0x03][0x00][UUID] + JSON) and
// dataschema = the version UUID.
func glueFramedEnvelope(t *testing.T, eventType, tenant, payload string) map[string]any {
	id := uuid.New()
	framed := append(append([]byte{0x03, 0x00}, id[:]...), payload...)
	data, err := json.Marshal(framed) // []byte -> base64 JSON string
	require.NoError(t, err)
	return map[string]any{
		"id": uuid.NewString(), "type": eventType, "source": "iam-org-membership", "specversion": "1",
		"tenant_id": tenant, "time": time.Now().UTC(), "data": json.RawMessage(data), "dataschema": id.String(),
	}
}

func startMembershipConsumer(t *testing.T, client *sqs.Client, qURL string, cache *fixtures.FakeCache) {
	startMembershipConsumerWith(t, client, qURL, cache, nil)
}

// startMembershipConsumerWith starts a membership consumer with dlq as
// Deps.DLQ (nil keeps the observe-only, SQS-redrive-only behaviour). It
// returns the channel Start's result arrives on.
func startMembershipConsumerWith(t *testing.T, client *sqs.Client, qURL string, cache *fixtures.FakeCache, dlq events.DLQPublisher) <-chan error {
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})
	deps := consumer.Deps{Client: client, Cache: cache, Log: fixtures.NoopLogger{}, Invalidator: inv, DLQ: dlq}
	deps.SQS.Region = "ap-south-1"
	deps.SQS.EndpointURL = endpointURL()
	deps.SQS.MaxMessages = 1
	deps.SQS.WaitSeconds = 1
	c, err := consumer.NewMembershipConsumer(qURL, deps, events.WithVisibilityTimeout(time.Second), events.WithConcurrency(1))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()
	t.Cleanup(func() { cancel(); _ = c.Stop() })
	return done
}

func newDLQPublisher(t *testing.T, client *sqs.Client) events.DLQPublisher {
	t.Helper()
	p, err := consumer.NewDLQPublisher(client, "iam-authz-enrichment-it", fixtures.NoopLogger{})
	require.NoError(t, err)
	return p
}

// receiveDLQ reads one message from dlqURL with its message attributes.
func receiveDLQ(t *testing.T, client *sqs.Client, dlqURL string) sqstypes.Message {
	t.Helper()
	var msg sqstypes.Message
	require.Eventually(t, func() bool {
		out, err := client.ReceiveMessage(context.Background(), &sqs.ReceiveMessageInput{
			QueueUrl: awssdk.String(dlqURL), MaxNumberOfMessages: 1, WaitTimeSeconds: 1,
			MessageAttributeNames: []string{"All"},
		})
		if err != nil || len(out.Messages) == 0 {
			return false
		}
		msg = out.Messages[0]
		return true
	}, 90*time.Second, 200*time.Millisecond, "nothing arrived in the DLQ")
	return msg
}

func dlqReason(m sqstypes.Message) string {
	if a, ok := m.MessageAttributes["DLQReason"]; ok && a.StringValue != nil {
		return *a.StringValue
	}
	return ""
}

// LLD §16 AE-36: a body that is not an envelope is forwarded to the queue's
// DLQ on its first receive — before forwarding, platform-events deleted it
// and the eviction it carried left no trace anywhere.
func TestSQS_DLQForwarding_MalformedBodyForwardedNotDeleted(t *testing.T) {
	client := newTestSQSClient(t)
	qURL, dlqURL := newRedriveQueue(t, client)
	startMembershipConsumerWith(t, client, qURL, fixtures.NewFakeCache(), newDLQPublisher(t, client))

	_, err := client.SendMessage(context.Background(), &sqs.SendMessageInput{QueueUrl: awssdk.String(qURL), MessageBody: awssdk.String("not an envelope")})
	require.NoError(t, err)

	msg := receiveDLQ(t, client, dlqURL)
	assert.Equal(t, "not an envelope", awssdk.ToString(msg.Body), "the original body is preserved")
	assert.True(t, strings.HasPrefix(dlqReason(msg), "malformed message body"), "DLQReason: %q", dlqReason(msg))
	require.Eventually(t, func() bool { return approxDepth(t, client, qURL) == "0/0" }, 30*time.Second, 300*time.Millisecond, "deleted from the source queue after the forward")
}

// With forwarding, a persistent failure is retried on deliveries 1-4 and
// forwarded by platform-events on the 5th (DLQReason names the receive count),
// instead of waiting for SQS's redrive.
func TestSQS_DLQForwarding_FifthDeliveryForwarded(t *testing.T) {
	client := newTestSQSClient(t)
	qURL, dlqURL := newRedriveQueue(t, client)
	cache := fixtures.NewFakeCache()
	cache.EvictCtxErr = errors.New("valkey unavailable")
	startMembershipConsumerWith(t, client, qURL, cache, newDLQPublisher(t, client))

	sendEnvelope(t, client, qURL, glueFramedEnvelope(t, "DepartmentMembershipGranted", "it-fwd-tenant", `{"user_id":"it-fwd-user"}`))

	msg := receiveDLQ(t, client, dlqURL)
	assert.Contains(t, dlqReason(msg), "exceeded consumer max receive count 4")
	evicts := 0
	for _, c := range cache.SortedCalls() {
		if strings.HasPrefix(c, "EvictMembershipContext:") {
			evicts++
		}
	}
	assert.Equal(t, 4, evicts, "the handler sees deliveries 1-4, DeadLetterHandler the 5th")
}

// With forwarding, a queue with no RedrivePolicy is a deployment error: the
// consumer refuses to start (cmd/server turns that into a pod restart via
// fatalErr) instead of running with nowhere to send poison messages.
func TestSQS_DLQForwarding_QueueWithoutRedrivePolicyFailsStart(t *testing.T) {
	client := newTestSQSClient(t)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	q, err := client.CreateQueue(context.Background(), &sqs.CreateQueueInput{QueueName: awssdk.String("it-authz-noredrive-" + suffix)})
	if err != nil {
		t.Skipf("skipping — no SQS emulator at %s (%v)", endpointURL(), err)
	}
	done := startMembershipConsumerWith(t, client, *q.QueueUrl, fixtures.NewFakeCache(), newDLQPublisher(t, client))

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, events.ErrDLQNotConfigured)
	case <-time.After(30 * time.Second):
		t.Fatal("Start kept running on a queue with no RedrivePolicy")
	}
}

// A Glue-encoded membership event — what iam-org-membership publishes once
// its registry is configured — is decoded, its eviction applied, and the
// message deleted. With the previous events.NoopCodec the framed bytes
// reached the handler unstripped and every such event dead-lettered.
func TestSQS_GlueEncodedMembershipEvent_EvictsCache(t *testing.T) {
	client := newTestSQSClient(t)
	qURL, _ := newRedriveQueue(t, client)
	cache := fixtures.NewFakeCache()
	tenant, user := "it-glue-tenant", "it-glue-user"
	cache.SeedMembershipContext(tenant, user, domain.MembershipContext{Roles: []string{"approver"}}, domain.CacheFresh)
	startMembershipConsumer(t, client, qURL, cache)

	sendEnvelope(t, client, qURL, glueFramedEnvelope(t, "DepartmentMembershipGranted", tenant, `{"user_id":"`+user+`"}`))

	require.Eventually(t, func() bool {
		_, res, _ := cache.GetMembershipContext(context.Background(), tenant, user)
		return res == domain.CacheMiss
	}, 30*time.Second, 200*time.Millisecond, "ae:ctx was never evicted — the Glue frame was not decoded")
	require.Eventually(t, func() bool { return approxDepth(t, client, qURL) == "0/0" }, 30*time.Second, 300*time.Millisecond, "message not deleted")
}

// A failure that persists is retried on deliveries 1-4; DeadLetterHandler
// observes the 5th (never acking it), and SQS's own RedrivePolicy then
// moves the message to the DLQ.
func TestSQS_DeadLetterHandler_ObservesLastDeliveryThenSQSRedrives(t *testing.T) {
	client := newTestSQSClient(t)
	qURL, dlqURL := newRedriveQueue(t, client)
	cache := fixtures.NewFakeCache()
	cache.EvictCtxErr = errors.New("valkey unavailable")
	startMembershipConsumer(t, client, qURL, cache)

	sendEnvelope(t, client, qURL, glueFramedEnvelope(t, "DepartmentMembershipGranted", "it-dlq-tenant", `{"user_id":"it-dlq-user"}`))

	require.Eventually(t, func() bool { return approxDepth(t, client, dlqURL) == "1/0" }, 90*time.Second, 500*time.Millisecond, "SQS never redrove the message")
	evicts := 0
	for _, c := range cache.SortedCalls() {
		if strings.HasPrefix(c, "EvictMembershipContext:") {
			evicts++
		}
	}
	assert.Equal(t, 4, evicts, "the handler sees deliveries 1-4, DeadLetterHandler the 5th")
}
