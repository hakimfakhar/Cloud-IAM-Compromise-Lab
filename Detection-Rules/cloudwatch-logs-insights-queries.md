# CloudWatch Logs Insights — Hunting Queries

These are the queries I used (or would use, if Logs Insights is wired to
the trail's log group) to reconstruct the `Service-account` identity's
full timeline from raw CloudTrail JSON. They're the direct equivalent of
the custom Wazuh rules from the RDP lab — instead of writing detection
logic client-side, this is querying AWS's own log store directly.

## 1. Full timeline for the compromised identity

```
fields @timestamp, eventName, eventSource, sourceIPAddress, errorCode
| filter userIdentity.userName = "Service-account"
| sort @timestamp asc
```

## 2. Isolate every denied/failed API call (privilege escalation attempts, etc.)

```
fields @timestamp, eventName, errorCode, errorMessage
| filter userIdentity.userName = "Service-account"
| filter ispresent(errorCode)
| sort @timestamp asc
```

## 3. Flag any `iam:AttachUserPolicy` or `iam:CreateAccessKey` call account-wide

These are the two highest-risk IAM APIs in this attack chain — a
production version of this query is a reasonable low-noise alert rule.

```
fields @timestamp, userIdentity.userName, eventName, requestParameters.policyArn
| filter eventName in ["AttachUserPolicy", "CreateAccessKey", "PutUserPolicy"]
| sort @timestamp desc
```

## 4. Confirm the CloudTrail Data-events gap directly from raw logs

Run this against the log group; an empty result for a known S3 object
key confirms Data events genuinely weren't captured (rather than just
not surfaced in the Event history UI):

```
fields @timestamp, eventName, requestParameters.key
| filter eventSource = "s3.amazonaws.com" and eventName = "GetObject"
| filter requestParameters.bucketName = "lab-sensitive-reports-hf01"
```
