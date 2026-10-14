//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func newSQSClient(t *testing.T) *sqs.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(envOr("AWS_REGION", "ap-south-1")),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			envOr("AWS_ACCESS_KEY_ID", "localstack"), envOr("AWS_SECRET_ACCESS_KEY", "localstack"), "")),
	)
	require.NoError(t, err)
	ep := endpointURL()
	return sqs.NewFromConfig(cfg, func(o *sqs.Options) { o.BaseEndpoint = awssdk.String(ep) })
}

// sendEvent publishes a minimal envelope matching platform-events'
// Envelope[json.RawMessage] wire shape directly to queueName — the same
// shape README.md's "Testing events locally" walkthrough sends by hand via
// `aws sqs send-message`.
func sendEvent(t *testing.T, queueName, eventType, tenant string, data any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"id":        uuid.NewString(),
		"type":      eventType,
		"source":    "e2e-test-publisher", // platform-events/v2 requires source; without it the message is deleted as malformed
		"tenant_id": tenant,
		"time":      time.Now().UTC().Format(time.RFC3339),
		"data":      data,
	})
	require.NoError(t, err)

	client := newSQSClient(t)
	_, err = client.SendMessage(context.Background(), &sqs.SendMessageInput{
		QueueUrl:    awssdk.String(queueURLEnv(queueName)),
		MessageBody: awssdk.String(string(body)),
	})
	require.NoError(t, err, "send %s to %s", eventType, queueName)
}
