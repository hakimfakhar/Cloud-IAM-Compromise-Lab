# MITRE ATT&CK for Cloud Mapping

Built from the guide's Appendix B, then filled in with the "Detected by"
column once GuardDuty's own `AttackSequence:IAM/CompromisedCredentials`
finding produced most of this mapping automatically.

| Stage | Tactic | Technique | API call | Detected by |
|---|---|---|---|---|
| 1 — Initial Access | Initial Access | T1078.004 — Valid Accounts: Cloud Accounts | `sts:GetCallerIdentity` | CloudTrail only (no standalone GuardDuty finding) |
| 2 — Recon | Discovery | T1526 — Cloud Service Discovery | `iam:ListUsers`, `ec2:DescribeInstances` | CloudTrail only |
| 2 — Recon | Discovery | T1069.003 — Permission Groups Discovery: Cloud Groups | `iam:ListAttachedUserPolicies` | CloudTrail only |
| 2 — Recon | Discovery | T1087.004 — Account Discovery: Cloud Account | `iam:GetAccountSummary` | CloudTrail only |
| 3 — Privilege Escalation | Privilege Escalation | T1098.003 — Account Manipulation: Additional Cloud Roles | `iam:AttachUserPolicy` (denied, then succeeded) | CloudTrail (both events); folded into GuardDuty's AttackSequence as corroborating evidence, no standalone finding |
| 4 — Data Access | Collection / Exfiltration | T1530 / T1567 — Data from Cloud Storage / Exfiltration Over Web Service | `s3:GetObject` | **Not logged by the CloudTrail trail** (Data events gap) — caught independently by GuardDuty S3 Protection: `PenTest:S3/KaliLinux` (Medium) |
| 5 — Persistence | Persistence | T1098.001 — Account Manipulation: Additional Cloud Credentials | `iam:CreateAccessKey` | GuardDuty: `PenTest:IAMUser/KaliLinux` (Medium) |
| Correlated | Initial Access, Persistence, Discovery, Exfiltration, Impact | T1078.004, T1098.001, T1098.003, T1087.004, T1526, T1565, T1567, T1069.003 | full sequence | GuardDuty: `AttackSequence:IAM/CompromisedCredentials` (**Critical**) |

## The honest gap

No individual reconnaissance call (Stage 2) ever triggered a standalone
GuardDuty finding on its own. That matches what the lab guide predicts:
a single read-only API call from a valid credential rarely looks
abnormal in isolation. What actually happened is more nuanced than
"GuardDuty missed it" — every recon call was captured and later folded
in as supporting evidence once the persistence and exfiltration stages
gave the `AttackSequence` correlation engine enough signal to connect
the whole chain retroactively (see the finding's "Indicators" tab,
`Screenshots/04-GuardDuty-Findings/07-attacksequence-resources.png`).
An analyst watching only for real-time, standalone alerts during
reconnaissance would have seen nothing until persistence/exfiltration
happened.
