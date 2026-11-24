"""Minimal SCIM 2.0 client, the same calls an IdP connector makes."""

import json
import urllib.error
import urllib.parse
import urllib.request

PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"


class ScimError(Exception):
    pass


class ScimClient:
    def __init__(self, base_url: str, token: str):
        self.base = base_url.rstrip("/") + "/scim/v2"
        self.token = token

    def _call(self, method, path, body=None, query=None):
        url = self.base + path + ("?" + urllib.parse.urlencode(query) if query else "")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/scim+json",
            "Accept": "application/scim+json",
        })
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                raw = r.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raise ScimError(f"{method} {path} -> {e.code}: {e.read().decode()[:200]}") from None

    # users
    def list_users(self):
        return self._call("GET", "/Users")["Resources"]

    def find_user(self, user_name):
        res = self._call("GET", "/Users", query={"filter": f'userName eq "{user_name}"'})["Resources"]
        return res[0] if res else None

    def create_user(self, user_name, given, family, employee_number):
        return self._call("POST", "/Users", {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", ENTERPRISE],
            "userName": user_name, "active": True,
            "name": {"givenName": given, "familyName": family},
            ENTERPRISE: {"employeeNumber": employee_number},
        })

    def set_active(self, user_id, active: bool):
        return self._call("PATCH", f"/Users/{user_id}", {
            "schemas": [PATCH_SCHEMA], "Operations": [{"op": "replace", "path": "active", "value": active}]})

    # groups
    def list_groups(self):
        return self._call("GET", "/Groups")["Resources"]

    def find_group(self, name):
        res = self._call("GET", "/Groups", query={"filter": f'displayName eq "{name}"'})["Resources"]
        return res[0] if res else None

    def ensure_group(self, name):
        return self.find_group(name) or self._call("POST", "/Groups", {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": name})

    def add_member(self, group_id, user_id):
        return self._call("PATCH", f"/Groups/{group_id}", {
            "schemas": [PATCH_SCHEMA], "Operations": [{"op": "add", "path": "members", "value": [{"value": user_id}]}]})

    def remove_member(self, group_id, user_id):
        return self._call("PATCH", f"/Groups/{group_id}", {
            "schemas": [PATCH_SCHEMA], "Operations": [{"op": "remove", "path": f'members[value eq "{user_id}"]'}]})
