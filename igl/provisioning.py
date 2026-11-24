"""Joiner / mover / leaver reconciliation: HR roster -> SCIM app.

HR is the source of truth. For each person, the desired access is
birthright + department role + title role (see policy.entitled_groups).
Provisioning owns only the groups named in the policy ("managed groups").
Anything else a user holds is an exception: provisioning leaves it alone and
the access certification campaign decides whether it stays.

Plan first, then apply. `dry_run=True` returns the plan and changes nothing.
"""

from dataclasses import dataclass, field

from .policy import entitled_groups, managed_groups


@dataclass
class Change:
    kind: str            # create_user | add_group | remove_group | deactivate | orphan
    user: str
    group: str = ""
    reason: str = ""


@dataclass
class Plan:
    changes: list[Change] = field(default_factory=list)

    def by_kind(self, kind):
        return [c for c in self.changes if c.kind == kind]

    def summary(self):
        kinds = ["create_user", "add_group", "remove_group", "deactivate", "orphan"]
        return {k: len(self.by_kind(k)) for k in kinds}


def build_plan(roster, policy, app_users) -> Plan:
    plan = Plan()
    managed = managed_groups(policy)
    by_name = {u["userName"].lower(): u for u in app_users}

    for email, person in sorted(roster.items()):
        app_user = by_name.get(email)
        want = entitled_groups(person, policy)

        if not person.active:
            if app_user and app_user["active"]:
                plan.changes.append(Change("deactivate", email, reason=f"leaver: terminated {person.end_date}"))
                for g in sorted(x["display"] for x in app_user["groups"]):
                    plan.changes.append(Change("remove_group", email, g, "leaver"))
            continue

        if not app_user:
            plan.changes.append(Change("create_user", email, reason=f"joiner: starts {person.start_date}"))
            have = set()
        else:
            have = {g["display"] for g in app_user["groups"]}

        for g in sorted(want - have):
            plan.changes.append(Change("add_group", email, g, f"policy: {person.department} / {person.title}"))
        for g in sorted((have & managed) - want):
            plan.changes.append(Change("remove_group", email, g,
                                       f"no longer entitled as {person.department} / {person.title}"))

    for name, u in sorted(by_name.items()):
        if name not in roster and u["active"]:
            plan.changes.append(Change("orphan", name, reason="active account with no HR record"))

    return plan


def apply_plan(plan: Plan, client, roster, log) -> dict:
    """Execute a plan through SCIM. Orphans are reported, never auto-deleted."""
    group_ids = {}

    def gid(name):
        if name not in group_ids:
            group_ids[name] = client.ensure_group(name)["id"]
        return group_ids[name]

    user_ids = {u["userName"].lower(): u["id"] for u in client.list_users()}
    done = {k: 0 for k in plan.summary()}

    for c in plan.changes:
        if c.kind == "create_user":
            p = roster[c.user]
            u = client.create_user(p.email, p.first_name, p.last_name, p.employee_id)
            user_ids[c.user] = u["id"]
        elif c.kind == "add_group":
            client.add_member(gid(c.group), user_ids[c.user])
        elif c.kind == "remove_group":
            client.remove_member(gid(c.group), user_ids[c.user])
        elif c.kind == "deactivate":
            client.set_active(user_ids[c.user], False)
        elif c.kind == "orphan":
            pass  # surfaced for the access review; deleting unknown accounts needs a human
        log.event(f"provision.{c.kind}", user=c.user, group=c.group, reason=c.reason)
        done[c.kind] += 1
    return done
