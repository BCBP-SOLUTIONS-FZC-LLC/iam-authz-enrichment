#!/bin/sh
# Creates the five §5 inbound queues, each with its own -dlq and a
# maxReceiveCount=5 redrive policy (§5) — pure infra config, no application
# code needed for DLQ behavior (see the doc comment on
# internal/adapter/inbound/consumer for why).
#
# Runs in two different contexts, hence the awslocal/aws fallback below:
#   - Local dev: mounted as a LocalStack ready.d hook (docker-compose.yml),
#     executed INSIDE the container, where `awslocal` exists.
#   - CI: the localstack container is a GitHub Actions `services:` peer —
#     Actions starts service containers before checkout runs, so this script
#     can't be mounted into it the same way. ci.yml instead checks out the
#     repo and runs this script directly on the bare runner against
#     localhost:4566, where only the standard `aws` CLI is available
#     (preinstalled on GitHub-hosted runners) — not `awslocal`.
set -e

if command -v awslocal >/dev/null 2>&1; then
  AWS="awslocal"
else
  AWS="aws --endpoint-url ${AWS_ENDPOINT_URL:-http://localhost:4566}"
fi

REGION="${AWS_DEFAULT_REGION:-ap-south-1}"
QUEUES="membership-authz-q user-authz-q billing-authz-q tenant-authz-q tender-authz-q"

for q in $QUEUES; do
  dlq_url=$($AWS sqs create-queue --queue-name "${q}-dlq" --region "$REGION" --query QueueUrl --output text)
  dlq_arn=$($AWS sqs get-queue-attributes --queue-url "$dlq_url" --attribute-names QueueArn --region "$REGION" --query Attributes.QueueArn --output text)

  $AWS sqs create-queue --queue-name "$q" --region "$REGION" \
    --attributes "{\"RedrivePolicy\":\"{\\\"deadLetterTargetArn\\\":\\\"$dlq_arn\\\",\\\"maxReceiveCount\\\":\\\"5\\\"}\"}"

  echo "created $q (-> ${q}-dlq, maxReceiveCount=5)"
done
