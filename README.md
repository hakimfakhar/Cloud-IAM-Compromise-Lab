# Cloud IAM Compromise Lab

**Simulating a leaked AWS IAM access key — from setup to a real CloudTrail detection gap.**

I built this on my own AWS free-tier account to mirror the structure of an
earlier RDP intrusion-detection lab I ran on Windows/Wazuh: build a
realistic misconfiguration, attack it myself from a Kali VM, then switch
to analyst mode and see what the detection stack actually caught — and
what it didn't.

## The headline finding

GuardDuty raised a **Critical** `AttackSequence:IAM/CompromisedCredentials`
finding correlating the entire attack chain — 5 MITRE tactics, 8
techniques, 6 high-risk APIs, one principal, one endpoint — automatically.

But the more interesting result came from CloudTrail, not GuardDuty: the
trail I configured for this lab logs **Management events only**, which is
the default and something I simply never turned on. That meant the S3
`GetObject` call during the exfiltration stage was **never logged by the
trail itself** — confirmed by an Event history search that came back with
zero matches. GuardDuty still caught it, but only because its S3
Protection feature analyzes S3 data-plane activity independently of the
trail's own Data events setting. Two detection sources, same fifteen
minutes of activity, two different answers — depending on which one you
trust.

Full writeup, including the exact CloudTrail timestamps and screenshots,
is in [`Reports/report.pdf`](Reports/report.pdf).

## What's in this repo

```
Cloud-IAM-Compromise-Lab/
├── README.md
├── Reports/
│   ├── report.tex          # full LaTeX source
│   └── report.pdf           # compiled report (21 pages)
├── Configuration/
│   ├── iam-setup.md                       # both IAM users, policies, the ARN bug
│   ├── lab-svc-acc-self-attach-policy.json # the custom privesc policy
│   └── logging-and-detection-config.md    # CloudTrail + GuardDuty config
├── Detection-Rules/
│   ├── mitre-attack-mapping.md            # full stage-by-stage MITRE table
│   └── cloudtrail-hunting-notes.md
└── Screenshots/
    ├── 01-Setup/               (11)
    ├── 02-Attack-Chain/        (15)
    ├── 03-CloudTrail-Hunt/     (10)
    ├── 04-GuardDuty-Findings/  (11)
    └── 05-Cleanup/             (3)
```

## The attack chain

| # | Stage | What I ran | Detected by |
|---|---|---|---|
| 1 | Initial Access | `sts get-caller-identity` | CloudTrail |
| 2 | Reconnaissance | `list-users`, `list-attached-user-policies`, `get-account-summary`, `s3 ls`, `describe-instances` | CloudTrail only — no standalone GuardDuty alert |
| 3 | Privilege Escalation | `attach-user-policy` (AdministratorAccess) — denied once due to a real ARN case-sensitivity bug, then succeeded | CloudTrail (both events); folded into GuardDuty's correlated finding |
| 4 | Data Access / Exfiltration | `s3 cp` of a "sensitive" report | **Not logged by the CloudTrail trail** — caught only by GuardDuty S3 Protection |
| 5 | Persistence | `create-access-key` — a second, admin-level backdoor key | GuardDuty (Medium finding) |

Full stage-by-stage MITRE ATT&CK mapping in
[`Detection-Rules/mitre-attack-mapping.md`](Detection-Rules/mitre-attack-mapping.md).

## Stack

- **AWS Free Tier** — IAM, CloudTrail, GuardDuty, S3
- **Kali Linux** (AWS CLI) as the attacker box
- Two named CLI profiles (`lab-admin`, `leaked-key`) kept strictly separate
  — every attack-chain command below was run with `--profile leaked-key`

## Why this scenario

A leaked/over-permissioned service-account access key is one of the most
common real-world cloud breach patterns. It's free-tier friendly, it maps
cleanly onto MITRE ATT&CK for Cloud, and — as it turned out — it had a
genuine, undocumented-by-me detection gap sitting in the default
CloudTrail configuration the whole time. I didn't go looking for that gap
on purpose; I found it while hunting for a call I already knew I'd made,
which is exactly how these gaps get found (or don't) in a real SOC.

## Cleanup

Torn down once documentation was complete — keys, users, buckets, trail,
and GuardDuty all removed and verified.

## About me

I'm Hakim Fakhar, a cybersecurity student working toward a SOC analyst
role. This lab (and the RDP intrusion-detection lab it's structured after)
are how I've been teaching myself detection engineering hands-on, one
platform at a time. Feedback welcome.
