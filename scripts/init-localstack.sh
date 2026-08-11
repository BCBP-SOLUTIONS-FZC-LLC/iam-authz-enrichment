#!/bin/sh
# LocalStack ready-hook: creates the five §5 inbound queues, each with its
# own -dlq and a maxReceiveCount=5 redrive policy (§5) — pure infra config,
# no application code needed for DLQ behavior (see the doc comment on
# internal/adapter/inbound/consumer for why).
set -e

REGION="${AWS_DEFAULT_REGION:-ap-south-1}"
QUEUES="membership-authz-q user-authz-q billing-authz-q tenant-authz-q tender-authz-q"

for q in $QUEUES; do
  dlq_url=$(awslocal sqs create-queue --queue-name "${q}-dlq" --region "$REGION" --query QueueUrl --output text)
  dlq_arn=$(awslocal sqs get-queue-attributes --queue-url "$dlq_url" --attribute-names QueueArn --region "$REGION" --query Attributes.QueueArn --output text)

  awslocal sqs create-queue --queue-name "$q" --region "$REGION" \
    --attributes "{\"RedrivePolicy\":\"{\\\"deadLetterTargetArn\\\":\\\"$dlq_arn\\\",\\\"maxReceiveCount\\\":\\\"5\\\"}\"}"

  echo "created $q (-> ${q}-dlq, maxReceiveCount=5)"
done
