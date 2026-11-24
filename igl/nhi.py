"""Non-human identity (NHI) audit: service accounts, app registrations, AI agents.

Machine identities now outnumber people in most tenants, and they fail in
predictable ways: nobody owns them, their secrets expire (or never do), they
hold tenant-wide permissions, and they keep running after their purpose ends.
"""

from datetime import date

HIGH_PRIV = {
    "Directory.ReadWrite.All", "User.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Mail.ReadWrite",
    "Mail.Send", "Files.ReadWrite.All", "Sites.FullControl.All", "Sites.ReadWrite.All",
}
WRITE_HINTS = ("ReadWrite", "Send", "FullControl")
SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def audit(identities, roster, as_of: date, unused_days=90, expiry_warn_days=30) -> list[dict]:
    findings = []

    def add(identity, severity, rule, detail, fix):
        findings.append({"identity": identity["name"], "type": identity["type"], "severity": severity,
                         "rule": rule, "detail": detail, "fix": fix})

    for i in identities:
        owner = (i.get("owner") or "").lower()
        cred = i.get("credential", {})
        perms = set(i.get("permissions", []))

        if not owner:
            add(i, "High", "NHI-01 No owner", "No accountable human owner on record",
                "Assign an owner before the next credential rotation; disable if nobody claims it in 14 days")
        elif owner not in roster or not roster[owner].active:
            add(i, "High", "NHI-02 Owner has left", f"Owner {owner} is not an active employee",
                "Reassign ownership to the team lead and review whether the identity is still needed")

        risky = sorted(perms & HIGH_PRIV)
        if risky:
            add(i, "High", "NHI-03 Tenant-wide permission", f"Holds {', '.join(risky)}",
                "Replace with the narrowest scope that works (e.g. Sites.Selected, a single mailbox)")

        exp = cred.get("expires")
        if exp is None:
            add(i, "Medium", "NHI-04 Credential never expires", f"{cred.get('kind', 'credential')} has no expiry",
                "Move to a certificate or managed identity with a set rotation period")
        else:
            left = (date.fromisoformat(exp) - as_of).days
            if left < 0:
                add(i, "High", "NHI-05 Credential expired", f"{cred['kind']} expired {exp} ({-left} days ago)",
                    "Rotate now, or retire the identity if nothing broke when it expired")
            elif left <= expiry_warn_days:
                add(i, "Medium", "NHI-06 Credential expiring", f"{cred['kind']} expires {exp} (in {left} days)",
                    "Rotate before expiry and record the new expiry date")

        if cred.get("kind") == "client_secret":
            created, exp = cred.get("created"), cred.get("expires")
            life = (date.fromisoformat(exp) - date.fromisoformat(created)).days if created and exp else None
            detail = "Uses a client secret" + (f" valid for {life} days" if life else "")
            add(i, "Medium" if life and life > 365 else "Low", "NHI-07 Secret instead of certificate", detail,
                "Use a certificate or workload identity federation; keep secret lifetimes at 6 months or less")

        last = i.get("last_used")
        if last and (as_of - date.fromisoformat(last)).days > unused_days:
            add(i, "Medium", "NHI-08 Unused", f"Last used {last} ({(as_of - date.fromisoformat(last)).days} days)",
                "Disable, wait one cycle for complaints, then delete")

        if i["type"] == "ai_agent" and any(h in p for p in perms for h in WRITE_HINTS) \
                and not i.get("human_approval_for_writes"):
            add(i, "High", "NHI-09 AI agent writes without approval",
                "Agent can send mail or change content with no human approval step",
                "Gate every write action behind human approval and log each tool call")

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["identity"], f["rule"]))
    return findings


def report(findings, identities, as_of: date) -> str:
    counts = {s: sum(f["severity"] == s for f in findings) for s in SEVERITY_ORDER}
    clean = sorted({i["name"] for i in identities} - {f["identity"] for f in findings})
    lines = [
        f"# Non-Human Identity Audit — {as_of.isoformat()}",
        "",
        f"- Identities reviewed: **{len(identities)}** (service accounts, app registrations, AI agents)",
        f"- Findings: **{counts['High']} High**, **{counts['Medium']} Medium**, **{counts['Low']} Low**",
        f"- No findings: {', '.join(clean) if clean else 'none'}",
        "",
        "| Severity | Identity | Rule | Detail | Fix |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f['severity']} | {f['identity']} | {f['rule']} | {f['detail']} | {f['fix']} |")
    return "\n".join(lines) + "\n"
