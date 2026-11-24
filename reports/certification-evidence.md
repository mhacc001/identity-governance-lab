# Access Certification Evidence — Northwind Workspace — 2026-11-24

- Items reviewed: **58** across **13** active accounts
- Decisions: **53 kept**, **5 revoked**, 0 left undecided
- Reviewers: 5 (managers from the HR roster; IAM team for accounts with no HR record)

## Risk flags found

| Flag | Count |
|---|---|
| inactive (over 90 days) | 7 |
| privileged | 5 |
| exception | 3 |
| orphan | 2 |

## Revoked access

| Item | User | Group | Flags | Reviewer |
|---|---|---|---|---|
| AR-019 | ethan.brooks@northwind.example | Tableau-Creator | exception,inactive-146d | maya.haddad@northwind.example |
| AR-021 | grace.okafor@northwind.example | Domain-Admins | privileged,exception | iam-team@northwind.example |
| AR-045 | noah.patel@northwind.example | NetSuite-Vendor-Admin | privileged,exception | grace.okafor@northwind.example |
| AR-057 | temp.auditor@northwind.example | Finance-SharePoint | orphan,inactive-267d | iam-team@northwind.example |
| AR-058 | temp.auditor@northwind.example | NetSuite-AP-Clerk | orphan,inactive-267d | iam-team@northwind.example |

## Flagged items kept, with the reviewer's reason

| Item | User | Group | SoD | Reviewer note |
|---|---|---|---|---|
| AR-014 | daniel.reyes@northwind.example | Okta-Super-Admin | — | Kept: privileged access confirmed as required for the role |
| AR-015 | ethan.brooks@northwind.example | All-Staff | — | Kept: role access confirmed by manager; account on 30-day watch for disable |
| AR-016 | ethan.brooks@northwind.example | M365-E3 | — | Kept: role access confirmed by manager; account on 30-day watch for disable |
| AR-017 | ethan.brooks@northwind.example | Sales-SharePoint | — | Kept: role access confirmed by manager; account on 30-day watch for disable |
| AR-018 | ethan.brooks@northwind.example | Salesforce-Sales-User | — | Kept: role access confirmed by manager; account on 30-day watch for disable |
| AR-043 | noah.patel@northwind.example | NetSuite-AP-Approver | SOD-01 | Kept: SoD conflict resolved by revoking AR-045 |
| AR-052 | sofia.martins@northwind.example | AWS-Prod-Admin | SOD-03 (mitigated) | Kept: designed SoD combination with mitigating control in place |
| AR-054 | sofia.martins@northwind.example | GitHub-Developers | SOD-03 (mitigated) | Kept: designed SoD combination with mitigating control in place |

Every decision is in `audit.jsonl` with a timestamp, the reviewer and the item ID.
