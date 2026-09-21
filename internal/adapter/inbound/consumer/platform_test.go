package consumer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPlatform_MapsSQSSNSOutboxThroughPlatformEvents(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ENDPOINT_URL", "http://localhost:4566")
	t.Setenv("SQS_MAX_MESSAGES", "7")
	t.Setenv("SQS_WAIT_SECONDS", "11")
	t.Setenv("SQS_VISIBILITY_TIMEOUT", "45s")
	t.Setenv("SQS_CONCURRENCY", "3")
	t.Setenv("SNS_TOPIC_ARN", "arn:aws:sns:ap-south-1:1:unused")
	t.Setenv("DATABASE_URL", "postgres://u:p@h:5432/db")
	t.Setenv("OUTBOX_POLL_INTERVAL", "2s")
	t.Setenv("OUTBOX_BATCH_SIZE", "10")
	t.Setenv("OUTBOX_MAX_ATTEMPTS", "3")
	t.Setenv("OUTBOX_DRAIN_TIMEOUT", "15s")
	t.Setenv("OUTBOX_PUBLISH_TIMEOUT", "8s")
	t.Setenv("OUTBOX_PUBLISH_CONCURRENCY", "2")
	t.Setenv("OUTBOX_STARTUP_JITTER", "1s")
	t.Setenv("OUTBOX_CLAIM_LEASE_DURATION", "2m")

	rec := &recordingLogger{}
	plat := LoadPlatform(rec, "ap-south-1", "http://floci:4571")

	assert.Equal(t, int32(7), plat.SQS.MaxMessages)
	assert.Equal(t, int32(11), plat.SQS.WaitSeconds)
	assert.Equal(t, 45*time.Second, plat.SQS.VisibilityTimeout)
	assert.Equal(t, 3, plat.SQS.Concurrency)
	assert.Equal(t, "ap-south-1", plat.SQS.Region, "this process's AWSRegion wins over LoadSQS's AWS_REGION")
	assert.Equal(t, "http://floci:4571", plat.SQS.EndpointURL)

	assert.Equal(t, "arn:aws:sns:ap-south-1:1:unused", plat.SNS.TopicARN)
	assert.Equal(t, "ap-south-1", plat.SNS.Region)
	assert.Equal(t, "http://floci:4571", plat.SNS.EndpointURL)
	assert.Equal(t, "arn:aws:sns:ap-south-1:1:unused", plat.SNSTopicARN)

	assert.Nil(t, plat.Outbox.Pool, "consume-only: RunnerConfigFromEnv must not invent a pool")
	assert.Nil(t, plat.Outbox.Publisher, "consume-only: RunnerConfigFromEnv must not invent a publisher")
	assert.Equal(t, 2*time.Second, plat.Outbox.PollInterval)
	assert.Equal(t, 10, plat.Outbox.BatchSize)
	assert.Equal(t, 3, plat.Outbox.MaxAttempts)
	assert.Equal(t, 15*time.Second, plat.Outbox.DrainTimeout)
	assert.Equal(t, 8*time.Second, plat.Outbox.PublishTimeout)
	assert.Equal(t, 2, plat.Outbox.PublishConcurrency)
	assert.Equal(t, time.Second, plat.Outbox.StartupJitter)
	assert.Equal(t, 2*time.Minute, plat.Outbox.ClaimLeaseDuration)
	assert.Equal(t, "postgres://u:p@h:5432/db", plat.OutboxDatabaseURL)
	assert.NotNil(t, plat.Outbox.Logger)
}

func TestLoadPlatform_NilLoggerAndEmptyPublisherEnv(t *testing.T) {
	t.Setenv("SNS_TOPIC_ARN", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("AWS_REGION", "eu-west-1")
	t.Setenv("AWS_ENDPOINT_URL", "")
	t.Setenv("SQS_MAX_MESSAGES", "not-an-int")
	t.Setenv("OUTBOX_BATCH_SIZE", "nope")

	plat := LoadPlatform(nil, "", "")
	assert.Empty(t, plat.SNSTopicARN)
	assert.Empty(t, plat.OutboxDatabaseURL)
	assert.Nil(t, plat.Outbox.Pool)
	assert.Nil(t, plat.Outbox.Publisher)
	assert.Empty(t, plat.SQS.Region)
	assert.Empty(t, plat.SQS.EndpointURL)
	assert.Equal(t, "eu-west-1", plat.SNS.Region, "empty override must leave LoadSNS's AWS_REGION")
	assert.Empty(t, plat.SNS.EndpointURL)
	require.NotEmpty(t, plat.SQS.Warnings, "invalid SQS_MAX_MESSAGES must surface via LoadSQS")
	assert.Equal(t, 50, plat.Outbox.BatchSize)
}

func TestLoadPlatform_LogsWarningsWhenLoggerSet(t *testing.T) {
	t.Setenv("SNS_TOPIC_ARN", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("SQS_MAX_MESSAGES", "xyz")
	t.Setenv("OUTBOX_MAX_ATTEMPTS", "xyz")

	rec := &recordingLogger{}
	_ = LoadPlatform(rec, "ap-south-1", "")
	require.NotEmpty(t, rec.warns, "LoadSQS/LoadOutbox warnings must go through LogWarningsTo")
}

func TestEventsLogger_NilSafeAndDelegates(t *testing.T) {
	t.Parallel()
	var zero eventsLogger
	zero.Debug("d", nil)
	zero.Info("i", nil)
	zero.Warn("w", nil)
	zero.Error("e", nil)

	rec := &recordingLogger{}
	l := eventsLogger{rec}
	l.Debug("d", nil)
	l.Info("i", nil)
	l.Warn("w", nil)
	l.Error("e", nil)
	assert.Equal(t, []string{"d"}, rec.debugs)
	assert.Equal(t, []string{"i"}, rec.infos)
	assert.Equal(t, []string{"w"}, rec.warns)
	assert.Equal(t, []string{"e"}, rec.errors)
}

func TestSNSPublisherSkipReason(t *testing.T) {
	t.Parallel()
	assert.Empty(t, SNSPublisherSkipReason(""))
	assert.Contains(t, SNSPublisherSkipReason("arn:aws:sns:x"), "NewSNSPublisher not started")
}

func TestOutboxRunnerSkipReason(t *testing.T) {
	t.Parallel()
	assert.Empty(t, OutboxRunnerSkipReason(""))
	assert.Contains(t, OutboxRunnerSkipReason("postgres://x"), "NewRunner / ApplySchema not started")
}

type recordingLogger struct {
	debugs []string
	warns  []string
	infos  []string
	errors []string
}

func (r *recordingLogger) Debug(msg string, _ map[string]interface{}) {
	r.debugs = append(r.debugs, msg)
}
func (r *recordingLogger) Info(msg string, _ map[string]interface{}) {
	r.infos = append(r.infos, msg)
}
func (r *recordingLogger) Warn(msg string, _ map[string]interface{}) {
	r.warns = append(r.warns, msg)
}
func (r *recordingLogger) Error(msg string, _ map[string]interface{}) {
	r.errors = append(r.errors, msg)
}
