# Append-only JSONL audit trail. Every autonomous agent decision is written here.
# "Every autonomous action is auditable" — healthcare/enterprise compliance requirement.

import json
import os
from datetime import datetime, timezone
from pathlib import Path

AUDIT_LOG_PATH = Path(os.getenv("PANACEA_AUDIT_LOG", "/tmp/panacea_audit.jsonl"))


def append_audit_entry(entry: dict) -> None:
    """Write one decision record to the append-only JSONL audit log."""
    entry.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, default=str) + "\n")


def read_audit_log(limit: int = 100) -> list[dict]:
    """Return the last `limit` entries from the audit log."""
    if not AUDIT_LOG_PATH.exists():
        return []
    entries = []
    with open(AUDIT_LOG_PATH, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries[-limit:]
