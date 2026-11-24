"""Command line for the Identity Governance Lab.

  python -m igl demo                       # full run against a local SCIM app, writes reports/
  python -m igl serve                      # start the SCIM app on :5070 (seeded with drift)
  python -m igl provision [--dry-run]      # HR roster -> SCIM app (joiner/mover/leaver)
  python -m igl certify start              # write reports/campaign.csv for reviewers
  python -m igl certify apply FILE         # revoke what reviewers rejected, write evidence
  python -m igl nhi                        # non-human identity audit
"""

import argparse
import json
import threading
import time
from datetime import date
from pathlib import Path

from .audit import AuditLog
from .certification import (accept_recommendations, apply_decisions, build_items, evidence_report,
                            read_campaign, write_campaign)
from .nhi import audit as nhi_audit
from .nhi import report as nhi_report
from .policy import load_policy, load_roster
from .provisioning import apply_plan, build_plan
from .scim_app import create_app
from .scim_client import ScimClient

ROOT = Path(__file__).resolve().parent.parent
DATA, REPORTS = ROOT / "data", ROOT / "reports"
TOKEN = "lab-token"


def start_server(port):
    app = create_app(DATA / "app_seed.json", token=TOKEN)
    threading.Thread(target=lambda: app.run(host="127.0.0.1", port=port, use_reloader=False), daemon=True).start()
    time.sleep(0.8)
    return f"http://127.0.0.1:{port}"


def print_plan(plan):
    for c in plan.changes:
        target = f" {c.group}" if c.group else ""
        print(f"  {c.kind:<13} {c.user}{target}  ({c.reason})")
    print("  summary:", plan.summary())


def cmd_provision(client, roster, policy, log, dry_run):
    plan = build_plan(roster, policy, client.list_users())
    print(f"[provision] plan ({'dry run' if dry_run else 'applying'}):")
    print_plan(plan)
    if not dry_run:
        print("[provision] applied:", apply_plan(plan, client, roster, log))
    return plan


def cmd_certify_start(client, roster, policy, as_of):
    items = build_items(roster, policy, client.list_users(), as_of)
    write_campaign(items, REPORTS / "campaign.csv")
    recs = {r: sum(i["recommendation"] == r for i in items) for r in ("keep", "review", "revoke")}
    print(f"[certify] {len(items)} review items -> reports/campaign.csv  recommendations: {recs}")
    return items


def cmd_certify_apply(client, log, path, as_of, accept):
    items = read_campaign(path)
    if accept:
        items = accept_recommendations(items)
        write_campaign(items, REPORTS / "campaign-decided.csv")
    result = apply_decisions(items, client, log)
    (REPORTS / "certification-evidence.md").write_text(evidence_report(items, as_of))
    print(f"[certify] applied: {result} -> reports/certification-evidence.md")


def cmd_nhi(roster, as_of):
    inv = json.loads((DATA / "nhi_inventory.json").read_text())["identities"]
    findings = nhi_audit(inv, roster, as_of)
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "nhi-audit.md").write_text(nhi_report(findings, inv, as_of))
    print(f"[nhi] {len(inv)} identities, {len(findings)} findings -> reports/nhi-audit.md")
    for f in findings:
        print(f"  {f['severity']:<6} {f['identity']:<24} {f['rule']}")


def snapshot(client, path):
    rows = []
    for u in sorted(client.list_users(), key=lambda x: x["userName"]):
        rows.append({"user": u["userName"], "active": u["active"], "groups": [g["display"] for g in u["groups"]]})
    path.write_text(json.dumps(rows, indent=2) + "\n")


def main():
    p = argparse.ArgumentParser(prog="igl", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", help="SCIM base URL of a running app (default: start a local one)")
    p.add_argument("--port", type=int, default=5070)
    p.add_argument("--as-of", default=None, help="review date YYYY-MM-DD (default: today)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo")
    sub.add_parser("serve")
    pv = sub.add_parser("provision")
    pv.add_argument("--dry-run", action="store_true")
    ce = sub.add_parser("certify")
    ce_sub = ce.add_subparsers(dest="step", required=True)
    ce_sub.add_parser("start")
    ap = ce_sub.add_parser("apply")
    ap.add_argument("file", type=Path)
    ap.add_argument("--accept-recommendations", action="store_true", help="act as reviewers (demo)")
    sub.add_parser("nhi")
    args = p.parse_args()

    as_of = date.fromisoformat(args.as_of) if args.as_of else date.today()
    roster = load_roster(DATA / "hr_roster.csv")
    policy = load_policy(DATA / "access_policy.json")
    REPORTS.mkdir(exist_ok=True)
    log = AuditLog(REPORTS / "audit.jsonl")

    if args.cmd == "serve":
        app = create_app(DATA / "app_seed.json", token=TOKEN)
        print(f"SCIM app on http://127.0.0.1:{args.port}/scim/v2  (bearer token: {TOKEN})")
        app.run(host="127.0.0.1", port=args.port)
        return
    if args.cmd == "nhi":
        cmd_nhi(roster, as_of)
        return

    client = ScimClient(args.url or start_server(args.port), TOKEN)

    if args.cmd == "provision":
        cmd_provision(client, roster, policy, log, args.dry_run)
    elif args.cmd == "certify" and args.step == "start":
        cmd_certify_start(client, roster, policy, as_of)
    elif args.cmd == "certify" and args.step == "apply":
        cmd_certify_apply(client, log, args.file, as_of, args.accept_recommendations)
    elif args.cmd == "demo":
        (REPORTS / "audit.jsonl").unlink(missing_ok=True)
        log = AuditLog(REPORTS / "audit.jsonl")
        snapshot(client, REPORTS / "state-0-before.json")
        print("== 1. Provisioning: HR roster -> SCIM app ==")
        cmd_provision(client, roster, policy, log, dry_run=False)
        snapshot(client, REPORTS / "state-1-after-provisioning.json")
        print("\n== 2. Access certification campaign ==")
        cmd_certify_start(client, roster, policy, as_of)
        cmd_certify_apply(client, log, REPORTS / "campaign.csv", as_of, accept=True)
        snapshot(client, REPORTS / "state-2-after-certification.json")
        print("\n== 3. Non-human identity audit ==")
        cmd_nhi(roster, as_of)
        print("\nAudit log: reports/audit.jsonl")


if __name__ == "__main__":
    main()
