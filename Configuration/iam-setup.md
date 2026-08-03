# IAM Configuration

## lab-admin
- Type: IAM user, console access enabled
- Permissions: `AdministratorAccess` (AWS managed, job function policy)
- Purpose: the only identity used to perform legitimate admin actions
  (creating the S3 bucket, uploading the "sensitive" report, cleanup).
  Root was never used after this user was created and MFA'd.

## Service-account
- Type: IAM user, **no console access** — programmatic access only
- Purpose: the "victim" identity. Represents a realistic over-permissioned
  service/reporting account whose access key gets leaked.
- Attached policies (initial):
  - `ReadOnlyAccess` (AWS managed)
  - `AmazonS3ReadOnlyAccess` (AWS managed)
- Attached policy (deliberate misconfiguration, added after initial setup):
  - `lab-svc-acc-self-attach-policy` — a narrowly-scoped **custom** policy
    granting `iam:AttachUserPolicy` on this user's own ARN only
    (see `lab-svc-acc-self-attach-policy.json`).

### The bug that delayed the privilege escalation

The first version of the custom policy's `Resource` ARN was written with
the wrong case:

```
arn:aws:iam::<ACCOUNT_ID>:user/service-account   <- wrong (lowercase "s")
arn:aws:iam::<ACCOUNT_ID>:user/Service-account   <- correct (matches IAM user name)
```

IAM resource ARNs are case-sensitive on the resource name. Because the
actual IAM user was created as `Service-account` (capital S), the
lowercase ARN in the policy never matched, and the first
`AttachUserPolicy` call failed with `AccessDenied` even though the policy
looked "attached enough" at a glance. Fixing the ARN casing
(`CreatePolicyVersion`) and re-running the same command succeeded.
This was not a scripted part of the lab — it was a real authoring mistake
that ended up producing a legitimate "failed then succeeded" privilege
escalation sequence in CloudTrail, which turned out to be more realistic
than a scripted denial would have been.

## CLI profiles

Two named AWS CLI profiles were used locally, never the default profile:

```
aws configure --profile lab-admin     # the admin identity
aws configure --profile leaked-key    # the "attacker", using Service-account's key
```

Every attack-chain command in `Reports/` was run with `--profile leaked-key`.
Every legitimate setup/cleanup action was run with `--profile lab-admin`.
No credentials are stored in this repository; screenshots showing key
material have the secret values blurred at the source.
