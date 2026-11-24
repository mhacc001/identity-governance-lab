"""HR roster + access policy: what each person *should* have."""

import csv
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Person:
    employee_id: str
    first_name: str
    last_name: str
    email: str
    department: str
    title: str
    manager_id: str
    status: str
    start_date: str
    end_date: str

    @property
    def active(self):
        return self.status == "active"


def load_roster(path: Path) -> dict[str, Person]:
    with open(path, newline="") as f:
        return {r["email"].lower(): Person(**r) for r in csv.DictReader(f)}


def load_policy(path: Path) -> dict:
    return json.loads(Path(path).read_text())


def managed_groups(policy) -> set[str]:
    """Every group that provisioning owns. Groups outside this set are exceptions."""
    out = set(policy["birthright"])
    for groups in policy["department_roles"].values():
        out |= set(groups)
    for groups in policy["title_roles"].values():
        out |= set(groups)
    return out


def entitled_groups(person: Person, policy) -> set[str]:
    """Birthright + department role + title role. Terminated people get nothing."""
    if not person.active:
        return set()
    groups = set(policy["birthright"])
    if person.department == "Contractors":
        groups -= set(policy.get("contractor_birthright_exclusions", []))
    groups |= set(policy["department_roles"].get(person.department, []))
    groups |= set(policy["title_roles"].get(person.title, []))
    return groups


def sod_violations(held: set[str], policy, entitled: set[str] = frozenset()) -> list[dict]:
    """SoD rules whose conflicting groups are all held.

    A conflict counts as mitigated only when the rule names a mitigating control
    AND the policy itself grants every group in the conflict (a designed
    combination, like SRE). A conflict that comes from a manual exception is
    never mitigated.
    """
    hits = []
    for rule in policy["sod_rules"]:
        if set(rule["groups"]) <= held:
            mitigated = bool(rule.get("mitigating_control")) and set(rule["groups"]) <= set(entitled)
            hits.append({**rule, "mitigated": mitigated})
    return hits
