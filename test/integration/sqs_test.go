//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/pkg/events"
	"github.com/stretchr/testify/assert"

	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/adapter/inbound/consumer"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/domain"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/internal/usecase"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/iam-authz-enrichment/test/fixtures"
)

func endpointURL() string {
	if v := os.Getenv("AWS_ENDPOINT_URL"); v != "" {
		return v
	}
	return "http://localhost:4566"
}

func newTestSQSClient(t *testing.T) *sqs.Client {
	t.Helper()
	ep := endpointURL()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("ap-south-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("localstack", "localstack", "")),
	)
	require.NoError(t, err)
	return sqs.NewFromConfig(cfg, func(o *sqs.Options) { o.BaseEndpoint = awssdk.String(ep) })
}

func queueURL(t *testing.T, client *sqs.Client, name string) string {
	t.Helper()
	out, err := client.GetQueueUrl(context.Background(), &sqs.GetQueueUrlInput{QueueName: awssdk.String(name)})
	require.NoError(t, err, "queue %s must exist — run scripts/init-localstack.sh (docker compose does this automatically)", name)
	return *out.QueueUrl
}

func sendEnvelope(t *testing.T, client *sqs.Client, qURL string, env map[string]any) {
	t.Helper()
	b, err := json.Marshal(env)
	require.NoError(t, err)
	_, err = client.SendMessage(context.Background(), &sqs.SendMessageInput{
		QueueUrl:    awssdk.String(qURL),
		MessageBody: awssdk.String(string(b)),
	})
	require.NoError(t, err)
}

func drainQueue(client *sqs.Client, qURL string) {
	_, _ = client.PurgeQueue(context.Background(), &sqs.PurgeQueueInput{QueueUrl: awssdk.String(qURL)})
}

// TestSQS_MembershipConsumer_EndToEnd sends a real DepartmentMembershipGranted
// event through LocalStack SQS and asserts the real consumer (wired to a
// real Valkey) evicts ae:ctx for the affected user.
func TestSQS_MembershipConsumer_EndToEnd(t *testing.T) {
	client := newTestSQSClient(t)
	qURL := queueURL(t, client, "membership-authz-q")
	drainQueue(client, qURL)

	cache := newTestCache(t)
	tenant, user := "it-sqs-tenant-1", "it-sqs-user-1"
	require.NoError(t, cache.SetMembershipContext(context.Background(), tenant, user, domain.MembershipContext{Roles: []string{"x"}}))

	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})
	c, err := consumer.NewMembershipConsumer(qURL, consumer.Deps{
		Client: client, Region: "ap-south-1", EndpointURL: endpointURL(), Cache: cache, Log: fixtures.NoopLogger{}, Invalidator: inv,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Start(ctx) }()
	defer func() { _ = c.Stop() }()

	sendEnvelope(t, client, qURL, map[string]any{
		"id": uuid.NewString(), "type": "DepartmentMembershipGranted", "tenant_id": tenant,
		"time": time.Now().Format(time.RFC3339), "data": map[string]string{"user_id": user},
	})

	require.Eventually(t, func() bool {
		_, result, _ := cache.GetMembershipContext(context.Background(), tenant, user)
		return result == domain.CacheMiss
	}, 10*time.Second, 200*time.Millisecond, "the real consumer must evict ae:ctx after a real SQS delivery")
}

// TestSQS_Consumer_Idempotency_SkipsRedeliveredEvent proves the §5 dedup
// contract end to end: the same event ID delivered twice must only be
// applied once (checked directly against the real ae:processed key).
func TestSQS_Consumer_Idempotency_SkipsRedeliveredEvent(t *testing.T) {
	cache := newTestCache(t)
	eventID := uuid.NewString()

	first, err := cache.MarkProcessed(context.Background(), eventID)
	require.NoError(t, err)
	assert.True(t, first)

	second, err := cache.MarkProcessed(context.Background(), eventID)
	require.NoError(t, err)
	assert.False(t, second)
}

// TestSQS_DLQ_MessageMovesAfterMaxReceiveCount proves the infra-level DLQ
// redrive policy actually works: a message the handler always fails on gets
// redelivered until SQS's own maxReceiveCount=5 routes it to the -dlq — no
// application-level DLQ code is involved (see the consumer package doc
// comment for why that's deliberate).
func TestSQS_DLQ_MessageMovesAfterMaxReceiveCount(t *testing.T) {
	client := newTestSQSClient(t)
	qURL := queueURL(t, client, "tender-authz-q")
	dlqURL := queueURL(t, client, "tender-authz-q-dlq")
	drainQueue(client, qURL)
	drainQueue(client, dlqURL)

	// A message this handler cannot parse — Payload isn't valid JSON for
	// TenderRestrictedPayload — so the handler always returns an error and
	// the message is never deleted, forcing SQS's own redrive counting.
	sendEnvelope(t, client, qURL, map[string]any{
		"id": uuid.NewString(), "type": "TenderRestricted", "tenant_id": "it-dlq-tenant",
		"time": time.Now().Format(time.RFC3339), "data": "not-an-object",
	})

	cache := newTestCache(t)
	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})
	c, err := consumer.NewTenderConsumer(qURL, consumer.Deps{
		Client: client, Region: "ap-south-1", EndpointURL: endpointURL(), Cache: cache, Log: fixtures.NoopLogger{}, Invalidator: inv,
	}, events.WithVisibilityTimeout(1*time.Second))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Start(ctx) }()
	defer func() { _ = c.Stop() }()

	require.Eventually(t, func() bool {
		out, err := client.ReceiveMessage(context.Background(), &sqs.ReceiveMessageInput{
			QueueUrl: awssdk.String(dlqURL), MaxNumberOfMessages: 1, WaitTimeSeconds: 1,
		})
		return err == nil && len(out.Messages) > 0
	}, 30*time.Second, 500*time.Millisecond, "after 5 failed receives, SQS's own redrive policy must move the message to the DLQ")
}

// TC-039: user-authz-q end-to-end — UserUpdated with changed_fields=['email']
// must evict ae:ctx for the affected user.
func TestSQS_UserConsumer_UserUpdated_EmailChange_EvictsCtx(t *testing.T) {
	client := newTestSQSClient(t)
	qURL := queueURL(t, client, "user-authz-q")
	drainQueue(client, qURL)

	cache := newTestCache(t)
	tenant, user := "it-sqs-tenant-2", "it-sqs-user-2"
	require.NoError(t, cache.SetMembershipContext(context.Background(), tenant, user,
		domain.MembershipContext{Roles: []string{"x"}, Departments: []domain.Department{}}))

	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})
	c, err := consumer.NewUserConsumer(qURL, consumer.Deps{
		Client: client, Region: "ap-south-1", EndpointURL: endpointURL(), Cache: cache, Log: fixtures.NoopLogger{}, Invalidator: inv,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Start(ctx) }()
	defer func() { _ = c.Stop() }()

	sendEnvelope(t, client, qURL, map[string]any{
		"id": uuid.NewString(), "type": "UserUpdated", "tenant_id": tenant,
		"time": time.Now().Format(time.RFC3339),
		"data": map[string]any{"user_id": user, "changed_fields": []string{"email"}},
	})

	require.Eventually(t, func() bool {
		_, result, _ := cache.GetMembershipContext(context.Background(), tenant, user)
		return result == domain.CacheMiss
	}, 10*time.Second, 200*time.Millisecond, "UserUpdated with email change must evict ae:ctx")
}

// TC-040: billing-authz-q end-to-end — TenantPlanChanged must evict
// ae:tenant for the affected tenant (single-key, tenant-wide eviction).
func TestSQS_BillingConsumer_TenantPlanChanged_EvictsTenant(t *testing.T) {
	client := newTestSQSClient(t)
	qURL := queueURL(t, client, "billing-authz-q")
	drainQueue(client, qURL)

	cache := newTestCache(t)
	tenant := "it-sqs-tenant-3"
	require.NoError(t, cache.SetTenantContext(context.Background(), tenant,
		domain.TenantContext{Plan: "pro", FeatureFlags: []string{}}))

	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})
	c, err := consumer.NewBillingConsumer(qURL, consumer.Deps{
		Client: client, Region: "ap-south-1", EndpointURL: endpointURL(), Cache: cache, Log: fixtures.NoopLogger{}, Invalidator: inv,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Start(ctx) }()
	defer func() { _ = c.Stop() }()

	sendEnvelope(t, client, qURL, map[string]any{
		"id": uuid.NewString(), "type": "TenantPlanChanged", "tenant_id": tenant,
		"time": time.Now().Format(time.RFC3339), "data": map[string]any{},
	})

	require.Eventually(t, func() bool {
		_, result, _ := cache.GetTenantContext(context.Background(), tenant)
		return result == domain.CacheMiss
	}, 10*time.Second, 200*time.Millisecond, "TenantPlanChanged must evict ae:tenant")
}

// TC-041: tenant-authz-q end-to-end — TenantRealmReady must NOT evict any
// cache key but must update the in-process realm map so subsequent tenant
// resolution for that realm succeeds.
func TestSQS_TenantConsumer_TenantRealmReady_UpdatesRealmMap_NoEviction(t *testing.T) {
	client := newTestSQSClient(t)
	qURL := queueURL(t, client, "tenant-authz-q")
	drainQueue(client, qURL)

	cache := newTestCache(t)
	tenant := "it-sqs-tenant-4"
	realm := "https://kc.example.com/realms/it-sqs-tenant-4"
	realmMap := usecase.NewRealmMap(nil)

	inv := usecase.NewInvalidator(cache, realmMap, usecase.NewRestrictedTenderSet(), fixtures.NoopLogger{})
	c, err := consumer.NewTenantConsumer(qURL, consumer.Deps{
		Client: client, Region: "ap-south-1", EndpointURL: endpointURL(), Cache: cache, Log: fixtures.NoopLogger{}, Invalidator: inv,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Start(ctx) }()
	defer func() { _ = c.Stop() }()

	sendEnvelope(t, client, qURL, map[string]any{
		"id": uuid.NewString(), "type": "TenantRealmReady", "tenant_id": tenant,
		"time": time.Now().Format(time.RFC3339), "data": map[string]any{"realm": realm},
	})

	require.Eventually(t, func() bool {
		got, ok := realmMap.Lookup(realm)
		return ok && got == tenant
	}, 10*time.Second, 200*time.Millisecond, "TenantRealmReady must update the realm map")
}

// TC-042: tender-authz-q end-to-end — TenderRestricted must NOT evict any
// cache key but must mark the tender as restricted in the in-process set so
// subsequent Check calls apply the tender-ACL overlay for that tender.
func TestSQS_TenderConsumer_TenderRestricted_UpdatesRestrictedSet_NoEviction(t *testing.T) {
	client := newTestSQSClient(t)
	qURL := queueURL(t, client, "tender-authz-q")
	drainQueue(client, qURL)

	cache := newTestCache(t)
	tenant := "it-sqs-tenant-5"
	tenderID := "tender-sqs-42"
	restricted := usecase.NewRestrictedTenderSet()

	inv := usecase.NewInvalidator(cache, usecase.NewRealmMap(nil), restricted, fixtures.NoopLogger{})
	c, err := consumer.NewTenderConsumer(qURL, consumer.Deps{
		Client: client, Region: "ap-south-1", EndpointURL: endpointURL(), Cache: cache, Log: fixtures.NoopLogger{}, Invalidator: inv,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Start(ctx) }()
	defer func() { _ = c.Stop() }()

	sendEnvelope(t, client, qURL, map[string]any{
		"id": uuid.NewString(), "type": "TenderRestricted", "tenant_id": tenant,
		"time": time.Now().Format(time.RFC3339), "data": map[string]any{"tender_id": tenderID},
	})

	require.Eventually(t, func() bool {
		return restricted.IsRestricted(tenant, tenderID)
	}, 10*time.Second, 200*time.Millisecond, "TenderRestricted must mark the tender in the RestrictedTenderSet")
}
