# Non-Human Identity Audit — 2026-11-24

- Identities reviewed: **5** (service accounts, app registrations, AI agents)
- Findings: **7 High**, **4 Medium**, **1 Low**
- No findings: svc-backup

| Severity | Identity | Rule | Detail | Fix |
|---|---|---|---|---|
| High | ai-agent-ticket-triage | NHI-03 Tenant-wide permission | Holds Mail.Send, Sites.ReadWrite.All | Replace with the narrowest scope that works (e.g. Sites.Selected, a single mailbox) |
| High | ai-agent-ticket-triage | NHI-09 AI agent writes without approval | Agent can send mail or change content with no human approval step | Gate every write action behind human approval and log each tool call |
| High | app-hr-sync | NHI-01 No owner | No accountable human owner on record | Assign an owner before the next credential rotation; disable if nobody claims it in 14 days |
| High | app-hr-sync | NHI-03 Tenant-wide permission | Holds Directory.ReadWrite.All, User.ReadWrite.All | Replace with the narrowest scope that works (e.g. Sites.Selected, a single mailbox) |
| High | app-sales-dashboard | NHI-05 Credential expired | client_secret expired 2026-10-31 (24 days ago) | Rotate now, or retire the identity if nothing broke when it expired |
| High | svc-legacy-ftp | NHI-02 Owner has left | Owner olivia.grant@northwind.example is not an active employee | Reassign ownership to the team lead and review whether the identity is still needed |
| High | svc-legacy-ftp | NHI-03 Tenant-wide permission | Holds Files.ReadWrite.All | Replace with the narrowest scope that works (e.g. Sites.Selected, a single mailbox) |
| Medium | app-hr-sync | NHI-06 Credential expiring | client_secret expires 2026-12-10 (in 16 days) | Rotate before expiry and record the new expiry date |
| Medium | app-hr-sync | NHI-07 Secret instead of certificate | Uses a client secret valid for 730 days | Use a certificate or workload identity federation; keep secret lifetimes at 6 months or less |
| Medium | svc-legacy-ftp | NHI-04 Credential never expires | password has no expiry | Move to a certificate or managed identity with a set rotation period |
| Medium | svc-legacy-ftp | NHI-08 Unused | Last used 2026-05-02 (206 days) | Disable, wait one cycle for complaints, then delete |
| Low | app-sales-dashboard | NHI-07 Secret instead of certificate | Uses a client secret valid for 365 days | Use a certificate or workload identity federation; keep secret lifetimes at 6 months or less |
