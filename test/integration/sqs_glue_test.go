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

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/pkg/events"

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
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil, 5*time.Second), usecase.NewRestrictedTenderSet(5*time.Second), fixtures.NoopLogger{})
	deps := consumer.Deps{Client: client, Cache: cache, Log: fixtures.NoopLogger{}, Invalidator: inv}
	deps.SQS.Region = "ap-south-1"
	deps.SQS.EndpointURL = endpointURL()
	deps.SQS.MaxMessages = 1
	deps.SQS.WaitSeconds = 1
	c, err := consumer.NewMembershipConsumer(qURL, deps, events.WithVisibilityTimeout(time.Second), events.WithConcurrency(1))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = c.Start(ctx) }()
	t.Cleanup(func() { cancel(); _ = c.Stop() })
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
