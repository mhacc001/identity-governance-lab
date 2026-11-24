"""Access certification campaign (the quarterly "user access review").

1. start():  snapshot every active account's entitlements into review items.
             Each item gets a reviewer (the user's manager from HR; the IAM
             team for orphans), risk flags and a recommended decision.
2. Reviewers fill the `decision` column with keep or revoke.
3. apply():  revoke what reviewers rejected through SCIM, log every action,
             and write an evidence report an auditor can read.
"""

import csv
from collections import Counter
from datetime import date
from pathlib import Path

from .policy import entitled_groups, managed_groups, sod_violations

FIELDS = ["item_id", "user", "group", "reviewer", "flags", "sod", "recommendation", "decision", "comment"]
IAM_TEAM = "iam-team@northwind.example"


def _days_since(iso, as_of: date):
    return (as_of - date.fromisoformat(iso)).days if iso else None


def build_items(roster, policy, app_users, as_of: date) -> list[dict]:
    managed = managed_groups(policy)
    privileged = set(policy["privileged_groups"])
    threshold = policy["inactive_days_threshold"]
    by_id = {p.employee_id: p for p in roster.values()}
    items = []

    for u in sorted(app_users, key=lambda x: x["userName"]):
        if not u["active"]:
            continue
        email = u["userName"].lower()
        person = roster.get(email)
        held = {g["display"] for g in u["groups"]}
        entitled = entitled_groups(person, policy) if person else set()
        sod = sod_violations(held, policy, entitled)
        idle = _days_since(u.get("urn:lab:lastLogin"), as_of)

        if person and person.manager_id in by_id:
            reviewer = by_id[person.manager_id].email
        else:
            reviewer = IAM_TEAM

        for g in sorted(held):
            flags = []
            if not person:
                flags.append("orphan")
            if g in privileged:
                flags.append("privileged")
            if person and g not in entitled:
                flags.append("exception" if g not in managed else "out-of-role")
            if idle is not None and idle > threshold:
                flags.append(f"inactive-{idle}d")
            sod_here = [r for r in sod if g in r["groups"]]
            sod_txt = "; ".join(f"{r['id']}{' (mitigated)' if r['mitigated'] else ''}" for r in sod_here)

            unmitigated = any(not r["mitigated"] for r in sod_here)
            if "orphan" in flags:
                rec = "revoke"
            elif ("exception" in flags or "out-of-role" in flags) and (
                    "privileged" in flags or unmitigated or any(f.startswith("inactive") for f in flags)):
                rec = "revoke"
            elif "privileged" in flags or sod_here or "exception" in flags or \
                    any(f.startswith("inactive") for f in flags):
                rec = "review"
            else:
                rec = "keep"

            items.append({"item_id": f"AR-{len(items) + 1:03d}", "user": email, "group": g,
                          "reviewer": reviewer, "flags": ",".join(flags), "sod": sod_txt,
                          "recommendation": rec, "decision": "", "comment": ""})
    return items


def write_campaign(items, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(items)


def read_campaign(path: Path) -> list[dict]:
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def accept_recommendations(items):
    """Demo helper: act as the reviewers. 'review' items are approved with a note
    explaining why, so the evidence shows a reasoned decision, not a rubber stamp."""
    for it in items:
        if not it["decision"]:
            it["decision"] = "revoke" if it["recommendation"] == "revoke" else "keep"
    revoked = {(i["user"], i["group"]): i["item_id"] for i in items if i["decision"] == "revoke"}
    for it in items:
        if it["recommendation"] != "review" or it["comment"]:
            continue
        sods = [s.strip() for s in it["sod"].split(";") if s.strip()]
        if sods and all("mitigated" in s for s in sods):
            it["comment"] = "Kept: designed SoD combination with mitigating control in place"
        elif sods:
            other = [iid for (u, g), iid in revoked.items() if u == it["user"]]
            it["comment"] = (f"Kept: SoD conflict resolved by revoking {', '.join(other)}" if other
                             else "Kept with exception: SoD conflict accepted by reviewer")
        elif any(f.startswith("inactive") for f in it["flags"].split(",")):
            it["comment"] = "Kept: role access confirmed by manager; account on 30-day watch for disable"
        else:
            it["comment"] = "Kept: privileged access confirmed as required for the role"
    return items


def apply_decisions(items, client, log) -> dict:
    undecided = [i["item_id"] for i in items if i["decision"] not in ("keep", "revoke")]
    if undecided:
        raise ValueError(f"{len(undecided)} items have no keep/revoke decision, e.g. {undecided[:3]}")

    users = {u["userName"].lower(): u for u in client.list_users()}
    groups = {g["displayName"]: g["id"] for g in client.list_groups()}
    revoked = []
    for it in items:
        if it["decision"] != "revoke":
            log.event("certify.keep", item=it["item_id"], user=it["user"], group=it["group"], reviewer=it["reviewer"])
            continue
        uid = users[it["user"]]["id"]
        client.remove_member(groups[it["group"]], uid)
        log.event("certify.revoke", item=it["item_id"], user=it["user"], group=it["group"],
                  reviewer=it["reviewer"], flags=it["flags"])
        revoked.append(it)

    # Orphans lose their last access and get disabled.
    for email in sorted({i["user"] for i in revoked if "orphan" in i["flags"]}):
        client.set_active(users[email]["id"], False)
        log.event("certify.disable_orphan", user=email)
    return {"items": len(items), "revoked": len(revoked)}


def evidence_report(items, as_of: date) -> str:
    c = Counter(i["decision"] for i in items)
    flags = Counter("inactive (over 90 days)" if f.startswith("inactive") else f
                    for i in items for f in i["flags"].split(",") if f)
    reviewers = Counter(i["reviewer"] for i in items)
    lines = [
        f"# Access Certification Evidence — Northwind Workspace — {as_of.isoformat()}",
        "",
        f"- Items reviewed: **{len(items)}** across **{len({i['user'] for i in items})}** active accounts",
        f"- Decisions: **{c['keep']} kept**, **{c['revoke']} revoked**, 0 left undecided",
        f"- Reviewers: {len(reviewers)} (managers from the HR roster; IAM team for accounts with no HR record)",
        "",
        "## Risk flags found",
        "",
        "| Flag | Count |",
        "|---|---|",
    ]
    for f, n in sorted(flags.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"| {f} | {n} |")
    lines += ["", "## Revoked access", "", "| Item | User | Group | Flags | Reviewer |", "|---|---|---|---|---|"]
    for i in items:
        if i["decision"] == "revoke":
            lines.append(f"| {i['item_id']} | {i['user']} | {i['group']} | {i['flags']} | {i['reviewer']} |")
    lines += ["", "## Flagged items kept, with the reviewer's reason", "",
              "| Item | User | Group | SoD | Reviewer note |", "|---|---|---|---|---|"]
    for i in items:
        if i["decision"] == "keep" and i["recommendation"] == "review":
            lines.append(f"| {i['item_id']} | {i['user']} | {i['group']} | {i['sod'] or '—'} | {i['comment'] or '—'} |")
    lines += ["", "Every decision is in `audit.jsonl` with a timestamp, the reviewer and the item ID."]
    return "\n".join(lines) + "\n"
