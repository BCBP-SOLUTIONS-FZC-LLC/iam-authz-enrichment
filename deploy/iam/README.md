# AWS IAM policy for iam-authz-enrichment

This directory holds the reference IAM policy that must be attached to the
service's IRSA role. The application does not create the role itself — that is
managed by platform Terraform. Copy the JSON in `policy.json` into the
Terraform module or apply it directly via `aws iam create-policy` /
`aws iam put-role-policy`.

The role is assumed by the service's Kubernetes ServiceAccount via IRSA. Wire
the ARN into Helm via `serviceAccount.annotations`:

```yaml
serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/iam-authz-enrichment
```

## Why this policy is so small

Unlike `iam-user-profile`, this service has no database, no S3 bucket, no
SNS topic (it publishes zero events — §5), and no Glue schema registry
(§ README "is this project integrated with platform-schemagov" — no, this
service publishes nothing to schema-govern). Its entire AWS footprint is
**consume-only** access to its five inbound SQS queues.

## Grants breakdown

| Action | Purpose | Introduced |
|---|---|---|
| `sqs:ReceiveMessage` / `DeleteMessage` / `GetQueueAttributes` / `ChangeMessageVisibility` | The five §5 event consumers (membership/user/billing/tenant/tender-authz-q) | v0.1.0 |
| `logs:CreateLogStream` / `PutLogEvents` | Container stdout to CloudWatch (if not using an OTel collector for logs) | v0.1.0 |

Deliberately **not** granted, and why:

| Not granted | Reason |
|---|---|
| `sqs:SendMessage` on any queue | This service publishes zero events (§5) — there is nothing to send |
| Any action on the five `-dlq` queues | DLQ routing is handled entirely by SQS's own native redrive policy (`RedrivePolicy` on the primary queue) — no application code ever calls an SQS API on a `-dlq` queue directly. See `internal/adapter/inbound/consumer`'s package doc comment and `ARCHITECTURE.md`'s "DLQ routing is infra-only" invariant |
| `s3:*` | No database, no signature/file storage of any kind |
| `sns:Publish` | No outbound events |
| `glue:*` | No schema registry integration |
| `kms:*` | Nothing here is KMS-encrypted by this service directly (Valkey/SQS encryption-at-rest, if any, is a platform-level infra concern, not an app-level IAM grant) |

## Valkey access

Valkey (`VALKEY_URL`) is reached over the network via a connection string
secret, not an AWS API call — there is no IAM action for it here. If the
platform's ElastiCache deployment uses IAM authentication (rather than a
security-group-scoped connection), add the corresponding
`elasticache:Connect` grant; this is not the default assumption in
`policy.json`.

## Rolling out a new queue

If a sixth inbound queue is ever added (see `CONTRIBUTING.md` § "Adding a new
§5 event type / consumer"), add its ARN to the `ConsumeAuthzEvents` statement's
`Resource` list in `policy.json` and to the Terraform `templatefile` call in
`policy.tf.example` — the IAM role must be updated before the new consumer is
deployed, or it will fail to start with an `AccessDenied` on its first
`ReceiveMessage` call.
