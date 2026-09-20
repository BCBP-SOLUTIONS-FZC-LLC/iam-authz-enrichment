package consumer

import (
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/pkg/config"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/pkg/events"
	"github.com/BCBP-SOLUTIONS-FZC-LLC/platform-events/pkg/outbox"
)

// PlatformConfig is the platform-events composition-root bundle
// iam-user-profile / iam-org-membership pass to NewSNSPublisher,
// outbox.NewRunner, and NewSQSConsumer.
//
// This service is consume-only (HLD §5.4 / EVT-2): SNS and outbox Configs
// are assembled through the same LoadSNS / SNSConfigFromEnv / LoadOutbox /
// RunnerConfigFromEnv helpers so SNS_* / OUTBOX_* knobs have one mapping,
// then cmd/server skips NewSNSPublisher, outbox.ApplySchema, and NewRunner.
type PlatformConfig struct {
	SQS    config.SQSConfigEnv
	SNS    events.SNSConfig
	Outbox outbox.Config
	// SNSTopicARN is the raw SNS_TOPIC_ARN LoadSNS read, so cmd/server can
	// warn if an operator set a publisher topic on a consume-only process.
	SNSTopicARN string
	// OutboxDatabaseURL is the raw DATABASE_URL LoadOutbox read.
	OutboxDatabaseURL string
}

// LoadPlatform loads SQS / SNS / outbox env through platform-events
// pkg/config — the same three Load* calls iam-user-profile /
// iam-org-membership make in cmd/server. region and endpointURL override
// the AWS_REGION / AWS_ENDPOINT_URL values LoadSNS/LoadSQS already read so
// this process's config.AWSRegion / AWSEndpointURL stay authoritative.
func LoadPlatform(log Logger, region, endpointURL string) PlatformConfig {
	sqsEnv := config.LoadSQS()
	snsEnv := config.LoadSNS()
	outboxEnv := config.LoadOutbox()

	var snsCfg events.SNSConfig
	var outboxCfg outbox.Config
	if log != nil {
		eventsLog := eventsLogger{log}
		config.LogWarningsTo(eventsLog, sqsEnv.Warnings)
		config.LogWarningsTo(eventsLog, outboxEnv.Warnings)
		snsCfg = config.SNSConfigFromEnv(snsEnv, eventsLog)
		// Pool and Publisher stay nil — RunnerConfigFromEnv still maps
		// every OUTBOX_* duration/int onto outbox.Config so a future
		// schema cannot bypass this helper with a hand-rolled
		// outbox.Config. cmd/server never passes this to NewRunner /
		// ApplySchema.
		outboxCfg = config.RunnerConfigFromEnv(outboxEnv, nil, nil, eventsLog)
	} else {
		config.LogWarningsTo(nil, sqsEnv.Warnings)
		config.LogWarningsTo(nil, outboxEnv.Warnings)
		snsCfg = config.SNSConfigFromEnv(snsEnv, nil)
		outboxCfg = config.RunnerConfigFromEnv(outboxEnv, nil, nil, nil)
	}

	sqsEnv.Region = region
	sqsEnv.EndpointURL = endpointURL
	if region != "" {
		snsCfg.Region = region
	}
	if endpointURL != "" {
		snsCfg.EndpointURL = endpointURL
	}

	return PlatformConfig{
		SQS:               sqsEnv,
		SNS:               snsCfg,
		Outbox:            outboxCfg,
		SNSTopicARN:       snsEnv.TopicARN,
		OutboxDatabaseURL: outboxEnv.DatabaseURL,
	}
}

// SNSPublisherSkipReason is non-empty when SNS_TOPIC_ARN is set on this
// consume-only process. cmd/server logs it and does not call
// events.NewSNSPublisher.
func SNSPublisherSkipReason(topicARN string) string {
	if topicARN == "" {
		return ""
	}
	return "SNS_TOPIC_ARN is set but iam-authz-enrichment publishes no events — platform-events NewSNSPublisher not started"
}

// OutboxRunnerSkipReason is non-empty when LoadOutbox saw a DATABASE_URL.
// cmd/server logs it and does not call outbox.ApplySchema / NewRunner.
func OutboxRunnerSkipReason(databaseURL string) string {
	if databaseURL == "" {
		return ""
	}
	return "OUTBOX DATABASE_URL is set but iam-authz-enrichment has no outbox (HLD §5.4 / EVT-2) — platform-events NewRunner / ApplySchema not started"
}

// eventsLogger is a concrete value that satisfies platform-events'
// pkg/config logger port (same Debug/Info/Warn/Error shape) so this
// package can pass consumer.Logger through LogWarningsTo /
// SNSConfigFromEnv / RunnerConfigFromEnv without importing the library's
// internal/ packages.
type eventsLogger struct{ Logger }

func (e eventsLogger) Debug(msg string, fields map[string]interface{}) {
	if e.Logger != nil {
		e.Logger.Debug(msg, fields)
	}
}

func (e eventsLogger) Info(msg string, fields map[string]interface{}) {
	if e.Logger != nil {
		e.Logger.Info(msg, fields)
	}
}

func (e eventsLogger) Warn(msg string, fields map[string]interface{}) {
	if e.Logger != nil {
		e.Logger.Warn(msg, fields)
	}
}

func (e eventsLogger) Error(msg string, fields map[string]interface{}) {
	if e.Logger != nil {
		e.Logger.Error(msg, fields)
	}
}
