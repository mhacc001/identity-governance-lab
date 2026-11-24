"""Append-only JSON Lines audit log for every governance action."""

import json
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def event(self, action: str, **fields):
        rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "action": action, **fields}
        with self.path.open("a") as f:
            f.write(json.dumps(rec) + "\n")
        return rec
