#!/usr/bin/env bash
# Floci ready-hook — provisions the five §5 inbound SQS queues, each with
# its own -dlq and a maxReceiveCount=5 redrive policy. Runs automatically
# on container start via the volume mount to /etc/floci/init/ready.d/.
#
# This service consumes only and publishes nothing (§1), so unlike
# iam-org-membership's/iam-delegation's own init-floci.sh there is no SNS
# topic/subscription and no Glue Schema Registry to provision here — just
# the same five plain queues scripts/init-localstack.sh already created,
# ported to floci's plain-`aws`-CLI convention (matching
# iam-org-membership/iam-delegation's own scripts/init-floci.sh).
#
# NOTE: this script is for the docker-compose `floci` service (local dev)
# only. CI (.github/workflows/validate-test.yml) runs a bare `localstack`
# service container directly and still uses scripts/init-localstack.sh —
# that script is untouched and continues to work independently of this one.

set -euo pipefail

AWS_REGION=ap-south-1
AWS_ACCOUNT=000000000000
MAX_RECEIVES=5

# The AWS CLI baked into the floci compat image defaults AWS_DEFAULT_REGION
# to us-east-1 regardless of the emulator's own FLOCI_DEFAULT_REGION — pin
# both region env vars so every `aws` call below lands in ap-south-1,
# matching FLOCI_DEFAULT_REGION/FLOCI_DEFAULT_ACCOUNT_ID on the container.
export AWS_DEFAULT_REGION="$AWS_REGION"
export AWS_REGION="$AWS_REGION"

queue_arn() { printf 'arn:aws:sqs:%s:%s:%s' "$AWS_REGION" "$AWS_ACCOUNT" "$1"; }

# provision_queue <queue-name>
# Creates <queue>-dlq then <queue> with RedrivePolicy → <queue>-dlq (max 5).
provision_queue() {
  local queue="$1"
  local dlq="${queue}-dlq"

  aws sqs create-queue --queue-name "$dlq" >/dev/null
  local dlq_arn
  dlq_arn=$(queue_arn "$dlq")

  local attrs
  attrs=$(mktemp)
  cat >"$attrs" <<EOF
{
  "RedrivePolicy": "{\"deadLetterTargetArn\":\"${dlq_arn}\",\"maxReceiveCount\":\"${MAX_RECEIVES}\"}"
}
EOF
  aws sqs create-queue --queue-name "$queue" --attributes "file://$attrs" >/dev/null
  rm -f "$attrs"

  echo "  Queue: $(aws sqs get-queue-url --queue-name "$queue" --output text)"
  echo "  DLQ:   $(aws sqs get-queue-url --queue-name "$dlq" --output text)"
}

echo "==> Inbound queues (this service consumes, §5):"
for q in membership-authz-q user-authz-q billing-authz-q tenant-authz-q tender-authz-q; do
  provision_queue "$q"
done

echo ""
echo "Floci init complete."
