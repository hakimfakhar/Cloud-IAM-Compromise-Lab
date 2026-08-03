# CloudTrail Hunting — What I Actually Did

I didn't query CloudWatch Logs Insights for this lab. My trail wasn't
wired to send logs to CloudWatch Logs, so the hunt was done entirely
through **CloudTrail's Event history** in the console: filtering by
event name and narrowing the time range to the window I ran the attack
chain in, then opening individual events to check `errorCode`,
`sourceIPAddress`, and `userIdentity`.

## What I searched for, in order

- `GetCallerIdentity` — confirmed Stage 1 landed at 14:52:29 UTC
- `ListUsers`, `ListAttachedUserPolicies`, `GetAccountSummary` — recon, Stage 2
- `AttachUserPolicy` — pulled every event with this name in the window,
  which is how I found the denied attempt sitting right next to the
  successful one, five minutes apart
- `CreateAccessKey` — Stage 5, and how I noticed lab-admin's own
  legitimate key-creation events sitting in the same list, which is what
  first tipped me off to check GuardDuty had told the two apart correctly
- `GetObjects` — searched this expecting to find the exfiltration
  download, and got zero matches. That's what led me to the Data events
  gap (see `logging-and-detection-config.md`), not a query — just an
  empty search result where I expected a hit.

Screenshots of each of these searches are in `Screenshots/03-CloudTrail-Hunt/`.

## What I'd add if I ran this again

Wiring the trail to CloudWatch Logs would let the same hunt be done with
actual Logs Insights queries instead of manual event-name filtering —
useful for anything wider than a single known identity in a known time
window. Rough sketches of what those queries would look like:

```
fields @timestamp, eventName, eventSource, sourceIPAddress, errorCode
| filter userIdentity.userName = "Service-account"
| sort @timestamp asc
```

```
fields @timestamp, userIdentity.userName, eventName
| filter eventName in ["AttachUserPolicy", "CreateAccessKey", "PutUserPolicy"]
| sort @timestamp desc
```

I haven't run either of these — they're what I'd reach for next time
rather than something this lab actually used.
