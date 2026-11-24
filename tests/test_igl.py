import json
from datetime import date
from pathlib import Path

import pytest

from igl.audit import AuditLog
from igl.certification import accept_recommendations, apply_decisions, build_items
from igl.nhi import audit as nhi_audit
from igl.policy import entitled_groups, load_policy, load_roster, sod_violations
from igl.provisioning import apply_plan, build_plan
from igl.scim_app import create_app

DATA = Path(__file__).resolve().parent.parent / "data"
AS_OF = date(2026, 11, 24)
TOKEN = "t"


class FlaskScim:
    """ScimClient twin that talks to the Flask app in-process (no network)."""

    def __init__(self, app):
        self.c = app.test_client()
        self.h = {"Authorization": f"Bearer {TOKEN}"}

    def _j(self, r, ok=(200, 201, 204)):
        assert r.status_code in ok, r.get_data(as_text=True)
        return r.get_json(silent=True)

    def list_users(self):
        return self._j(self.c.get("/scim/v2/Users", headers=self.h))["Resources"]

    def list_groups(self):
        return self._j(self.c.get("/scim/v2/Groups", headers=self.h))["Resources"]

    def ensure_group(self, name):
        found = [g for g in self.list_groups() if g["displayName"] == name]
        return found[0] if found else self._j(self.c.post("/scim/v2/Groups", json={"displayName": name}, headers=self.h))

    def create_user(self, user_name, given, family, emp):
        return self._j(self.c.post("/scim/v2/Users", json={"userName": user_name, "name": {
            "givenName": given, "familyName": family}}, headers=self.h))

    def set_active(self, uid, active):
        return self._j(self.c.patch(f"/scim/v2/Users/{uid}", headers=self.h, json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": active}]}))

    def add_member(self, gid, uid):
        return self._j(self.c.patch(f"/scim/v2/Groups/{gid}", headers=self.h, json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "add", "path": "members", "value": [{"value": uid}]}]}))

    def remove_member(self, gid, uid):
        return self._j(self.c.patch(f"/scim/v2/Groups/{gid}", headers=self.h, json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "remove", "path": f'members[value eq "{uid}"]'}]}))


@pytest.fixture
def env(tmp_path):
    app = create_app(DATA / "app_seed.json", token=TOKEN)
    return {"app": app, "client": FlaskScim(app), "roster": load_roster(DATA / "hr_roster.csv"),
            "policy": load_policy(DATA / "access_policy.json"), "log": AuditLog(tmp_path / "audit.jsonl")}


def groups_of(client, email):
    u = next(x for x in client.list_users() if x["userName"] == email)
    return u["active"], {g["display"] for g in u["groups"]}


def test_scim_rejects_missing_token(env):
    assert env["app"].test_client().get("/scim/v2/Users").status_code == 401


def test_scim_filter_and_duplicate(env):
    c = env["app"].test_client()
    h = {"Authorization": f"Bearer {TOKEN}"}
    r = c.get('/scim/v2/Users?filter=userName eq "liam.chen@northwind.example"', headers=h).get_json()
    assert r["totalResults"] == 1
    assert c.post("/scim/v2/Users", json={"userName": "liam.chen@northwind.example"}, headers=h).status_code == 409


def test_plan_covers_joiner_mover_leaver_and_orphan(env):
    plan = build_plan(env["roster"], env["policy"], env["client"].list_users())
    kinds = {(c.kind, c.user, c.group) for c in plan.changes}
    assert ("create_user", "priya.raman@northwind.example", "") in kinds                      # joiner
    assert ("remove_group", "lucas.moreau@northwind.example", "GitHub-Developers") in kinds  # mover
    assert ("add_group", "lucas.moreau@northwind.example", "Salesforce-Sales-User") in kinds
    assert ("deactivate", "olivia.grant@northwind.example", "") in kinds                     # leaver
    assert ("orphan", "temp.auditor@northwind.example", "") in kinds
    # unmanaged exceptions are left for the access review, not silently removed
    assert ("remove_group", "grace.okafor@northwind.example", "Domain-Admins") not in kinds


def test_dry_run_changes_nothing(env):
    before = json.dumps(env["client"].list_users(), sort_keys=True)
    build_plan(env["roster"], env["policy"], env["client"].list_users())
    assert json.dumps(env["client"].list_users(), sort_keys=True) == before


def test_apply_plan_reaches_desired_state(env):
    c = env["client"]
    plan = build_plan(env["roster"], env["policy"], c.list_users())
    apply_plan(plan, c, env["roster"], env["log"])
    active, groups = groups_of(c, "olivia.grant@northwind.example")
    assert not active and not groups
    assert groups_of(c, "priya.raman@northwind.example")[1] == entitled_groups(
        env["roster"]["priya.raman@northwind.example"], env["policy"])
    # a second run has nothing left to do except report the orphan
    again = build_plan(env["roster"], env["policy"], c.list_users())
    assert [x.kind for x in again.changes] == ["orphan"]


def test_sod_mitigation_only_for_designed_combinations(env):
    policy = env["policy"]
    sre = env["roster"]["sofia.martins@northwind.example"]
    hits = sod_violations({"GitHub-Developers", "AWS-Prod-Admin"}, policy, entitled_groups(sre, policy))
    assert hits[0]["id"] == "SOD-03" and hits[0]["mitigated"]
    dev = env["roster"]["liam.chen@northwind.example"]
    hits = sod_violations({"GitHub-Developers", "AWS-Prod-Admin"}, policy, entitled_groups(dev, policy))
    assert not hits[0]["mitigated"]


def test_certification_revokes_and_disables_orphan(env):
    c = env["client"]
    apply_plan(build_plan(env["roster"], env["policy"], c.list_users()), c, env["roster"], env["log"])
    items = accept_recommendations(build_items(env["roster"], env["policy"], c.list_users(), AS_OF))
    result = apply_decisions(items, c, env["log"])
    assert result["revoked"] == 5
    assert "NetSuite-Vendor-Admin" not in groups_of(c, "noah.patel@northwind.example")[1]
    assert "Domain-Admins" not in groups_of(c, "grace.okafor@northwind.example")[1]
    assert groups_of(c, "temp.auditor@northwind.example") == (False, set())
    assert '"action": "certify.revoke"' in env["log"].path.read_text()


def test_certification_refuses_undecided_items(env):
    items = build_items(env["roster"], env["policy"], env["client"].list_users(), AS_OF)
    with pytest.raises(ValueError):
        apply_decisions(items, env["client"], env["log"])


def test_nhi_rules(env):
    inv = json.loads((DATA / "nhi_inventory.json").read_text())["identities"]
    found = {(f["identity"], f["rule"].split()[0]) for f in nhi_audit(inv, env["roster"], AS_OF)}
    assert ("app-hr-sync", "NHI-01") in found          # no owner
    assert ("svc-legacy-ftp", "NHI-02") in found       # owner was terminated
    assert ("app-sales-dashboard", "NHI-05") in found  # expired secret
    assert ("ai-agent-ticket-triage", "NHI-09") in found
    assert not any(i == "svc-backup" for i, _ in found)
