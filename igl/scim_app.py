"""A small SCIM 2.0 service provider (RFC 7643 / 7644) standing in for a SaaS app.

Okta, Microsoft Entra ID and SailPoint provision apps through exactly these
endpoints, so the provisioning engine in this lab speaks real SCIM:

  GET/POST          /scim/v2/Users            (filter: userName eq "...")
  GET/PATCH/DELETE  /scim/v2/Users/<id>       (PATCH replace active, name, ...)
  GET/POST          /scim/v2/Groups           (filter: displayName eq "...")
  GET/PATCH         /scim/v2/Groups/<id>      (PATCH add/remove members)
  GET               /scim/v2/ServiceProviderConfig

State is in memory and seeded from data/app_seed.json. Every request needs the
bearer token, like a real provisioning connector.
"""

import json
import re
import uuid
from pathlib import Path

from flask import Flask, jsonify, request

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

FILTER_RX = re.compile(r'^\s*(userName|displayName)\s+eq\s+"([^"]*)"\s*$')


def scim_error(status, detail):
    return jsonify({"schemas": [ERROR_SCHEMA], "status": str(status), "detail": detail}), status


def create_app(seed_path: Path | None = None, token: str = "lab-token") -> Flask:
    app = Flask(__name__)
    users: dict[str, dict] = {}
    groups: dict[str, dict] = {}

    def group_by_name(name):
        return next((g for g in groups.values() if g["displayName"] == name), None)

    def ensure_group(name):
        g = group_by_name(name)
        if not g:
            g = {"id": str(uuid.uuid4()), "displayName": name, "members": []}
            groups[g["id"]] = g
        return g

    def user_view(u):
        member_of = [{"value": g["id"], "display": g["displayName"]}
                     for g in groups.values() if any(m["value"] == u["id"] for m in g["members"])]
        return {
            "schemas": [USER_SCHEMA, ENTERPRISE],
            "id": u["id"],
            "userName": u["userName"],
            "name": {"givenName": u.get("givenName", ""), "familyName": u.get("familyName", "")},
            "active": u["active"],
            "groups": sorted(member_of, key=lambda x: x["display"]),
            ENTERPRISE: {"employeeNumber": u.get("employeeNumber", "")},
            "urn:lab:lastLogin": u.get("lastLogin"),
            "meta": {"resourceType": "User", "location": f"/scim/v2/Users/{u['id']}"},
        }

    def group_view(g):
        return {"schemas": [GROUP_SCHEMA], "id": g["id"], "displayName": g["displayName"],
                "members": g["members"], "meta": {"resourceType": "Group"}}

    def list_response(items):
        return jsonify({"schemas": [LIST_SCHEMA], "totalResults": len(items),
                        "startIndex": 1, "itemsPerPage": len(items), "Resources": items})

    if seed_path:
        seed = json.loads(Path(seed_path).read_text())
        for s in seed["users"]:
            uid = str(uuid.uuid4())
            users[uid] = {"id": uid, **{k: v for k, v in s.items() if k != "groups"}}
            for gname in s["groups"]:
                ensure_group(gname)["members"].append({"value": uid, "display": s["userName"]})

    @app.before_request
    def auth():
        if request.headers.get("Authorization") != f"Bearer {token}":
            return scim_error(401, "Missing or invalid bearer token")

    @app.get("/scim/v2/ServiceProviderConfig")
    def spc():
        return jsonify({"patch": {"supported": True}, "filter": {"supported": True, "maxResults": 200},
                        "bulk": {"supported": False}, "authenticationSchemes": [{"type": "oauthbearertoken"}]})

    # ---- Users ----
    @app.get("/scim/v2/Users")
    def list_users():
        f = request.args.get("filter")
        items = list(users.values())
        if f:
            m = FILTER_RX.match(f)
            if not m or m.group(1) != "userName":
                return scim_error(400, "Only 'userName eq \"...\"' filters are supported")
            items = [u for u in items if u["userName"].lower() == m.group(2).lower()]
        return list_response([user_view(u) for u in items])

    @app.post("/scim/v2/Users")
    def create_user():
        body = request.get_json(force=True)
        if not body.get("userName"):
            return scim_error(400, "userName is required")
        if any(u["userName"].lower() == body["userName"].lower() for u in users.values()):
            return scim_error(409, "userName already exists")
        uid = str(uuid.uuid4())
        users[uid] = {"id": uid, "userName": body["userName"], "active": body.get("active", True),
                      "givenName": body.get("name", {}).get("givenName", ""),
                      "familyName": body.get("name", {}).get("familyName", ""),
                      "employeeNumber": body.get(ENTERPRISE, {}).get("employeeNumber", ""),
                      "lastLogin": None}
        return jsonify(user_view(users[uid])), 201

    @app.get("/scim/v2/Users/<uid>")
    def get_user(uid):
        u = users.get(uid)
        return jsonify(user_view(u)) if u else scim_error(404, "User not found")

    @app.patch("/scim/v2/Users/<uid>")
    def patch_user(uid):
        u = users.get(uid)
        if not u:
            return scim_error(404, "User not found")
        body = request.get_json(force=True)
        if PATCH_SCHEMA not in body.get("schemas", []):
            return scim_error(400, "PatchOp schema required")
        for op in body.get("Operations", []):
            if op.get("op", "").lower() != "replace":
                return scim_error(400, "Only replace is supported on Users")
            value = op.get("value", {})
            path = op.get("path")
            if path:
                value = {path: op.get("value")}
            for k, v in value.items():
                if k == "active":
                    u["active"] = bool(v)
                elif k == "name.givenName":
                    u["givenName"] = v
                elif k == "name.familyName":
                    u["familyName"] = v
                else:
                    return scim_error(400, f"Unsupported attribute: {k}")
        return jsonify(user_view(u))

    @app.delete("/scim/v2/Users/<uid>")
    def delete_user(uid):
        if uid not in users:
            return scim_error(404, "User not found")
        for g in groups.values():
            g["members"] = [m for m in g["members"] if m["value"] != uid]
        del users[uid]
        return "", 204

    # ---- Groups ----
    @app.get("/scim/v2/Groups")
    def list_groups():
        f = request.args.get("filter")
        items = list(groups.values())
        if f:
            m = FILTER_RX.match(f)
            if not m or m.group(1) != "displayName":
                return scim_error(400, "Only 'displayName eq \"...\"' filters are supported")
            items = [g for g in items if g["displayName"] == m.group(2)]
        return list_response([group_view(g) for g in items])

    @app.post("/scim/v2/Groups")
    def create_group():
        body = request.get_json(force=True)
        if not body.get("displayName"):
            return scim_error(400, "displayName is required")
        if group_by_name(body["displayName"]):
            return scim_error(409, "Group already exists")
        g = ensure_group(body["displayName"])
        return jsonify(group_view(g)), 201

    @app.get("/scim/v2/Groups/<gid>")
    def get_group(gid):
        g = groups.get(gid)
        return jsonify(group_view(g)) if g else scim_error(404, "Group not found")

    @app.patch("/scim/v2/Groups/<gid>")
    def patch_group(gid):
        g = groups.get(gid)
        if not g:
            return scim_error(404, "Group not found")
        body = request.get_json(force=True)
        if PATCH_SCHEMA not in body.get("schemas", []):
            return scim_error(400, "PatchOp schema required")
        for op in body.get("Operations", []):
            kind = op.get("op", "").lower()
            if kind == "add" and op.get("path") == "members":
                for m in op.get("value", []):
                    if m["value"] not in users:
                        return scim_error(404, f"User {m['value']} not found")
                    if not any(x["value"] == m["value"] for x in g["members"]):
                        g["members"].append({"value": m["value"], "display": users[m["value"]]["userName"]})
            elif kind == "remove":
                path = op.get("path", "")
                m = re.match(r'members\[value eq "([^"]+)"\]', path)
                if not m:
                    return scim_error(400, "remove needs path members[value eq \"<id>\"]")
                g["members"] = [x for x in g["members"] if x["value"] != m.group(1)]
            else:
                return scim_error(400, f"Unsupported operation: {op}")
        return jsonify(group_view(g))

    return app
