# CloudTrail & GuardDuty Configuration

## CloudTrail — trail `lab-trail`

| Setting | Value |
|---|---|
| Trail name | `lab-trail` |
| Home region | Europe (Stockholm) — `eu-north-1` |
| Multi-region trail | Yes |
| Management events | All (Read and Write) |
| Data events | **Not configured** |
| Log file validation | Enabled |
| Storage | Dedicated S3 bucket, auto-created (`aws-cloudtrail-logs-<account-id>-...`) |

Leaving **Data events** unconfigured was not something I set out to
demonstrate — it's simply the default state of a trail unless you turn
data events on explicitly, and I didn't turn them on. That default became
the most useful finding in the whole lab: it meant the S3 `GetObject` call
during the exfiltration stage was never written to the trail at all
(confirmed by an `Event history` search for `GetObjects` returning
"No matches" — see `Screenshots/03-CloudTrail-Hunt/10-getobjects-no-matches.png`),
even though every IAM management call around it was captured perfectly.

## GuardDuty

Enabled with default settings (30-day free trial, no extra configuration).
GuardDuty ingests CloudTrail management events, VPC Flow Logs, and DNS
logs automatically, and — separately from CloudTrail's own Data events
setting — also runs its own **S3 Protection** analysis directly on S3
data-plane activity. That's the specific reason GuardDuty still generated
findings for the `GetObject`/`PutObject` calls that CloudTrail's trail
never logged: S3 Protection doesn't depend on trail-level Data events
being turned on. This distinction is the core of Finding 2 in the report.

## Why `eu-north-1` / Stockholm

No specific reason beyond it being the default region suggested during
account setup for a Europe-based account; it doesn't affect any of the
findings and is called out here only because it appears in ARNs
throughout the screenshots.
