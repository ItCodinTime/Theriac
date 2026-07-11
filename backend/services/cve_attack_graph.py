"""CVE ↔ attack correlation helpers — device → CVE → probed port graph edges."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

BACKEND_ROOT = Path(__file__).resolve().parent.parent
CVE_PATH = BACKEND_ROOT / "cves.json"

# Ports named in CVE mitigations even when the CVE record's port field is null.
_MITIGATION_PORT_HINTS: dict[str, set[int]] = {
    "CVE-2018-10597": {24105, 24005, 22, 3200},
    "CVE-2020-16222": {22, 3200, 24105, 24005},
    "CVE-2020-16220": {22, 3200},
}


@lru_cache(maxsize=1)
def _load_cve_records() -> list[dict[str, Any]]:
    try:
        return json.loads(CVE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


def correlate_cves_for_port(
    device_model: str,
    port: int,
    *,
    firmware_version: str = "",
) -> list[dict[str, Any]]:
    """Return CVE records that bind this device/port (exact port or mitigation hint)."""
    device = (device_model or "").strip().lower()
    device_slug = re.sub(r"[^a-z0-9]+", "_", device)
    hits: list[dict[str, Any]] = []

    for record in _load_cve_records():
        cve_id = str(record.get("cve_id") or "")
        rec_device = str(record.get("device_model") or "").strip().lower()
        rec_slug = re.sub(r"[^a-z0-9]+", "_", rec_device)
        # Match same device family, or generic embedded linux for SSH-class CVEs.
        device_ok = (
            rec_slug == device_slug
            or (rec_slug == "generic_embedded_linux" and port == 22)
            or ("intellivue" in device_slug and "intellivue" in rec_slug)
        )
        if not device_ok:
            continue

        rec_port = record.get("port")
        hinted = _MITIGATION_PORT_HINTS.get(cve_id, set())
        port_ok = (rec_port is not None and int(rec_port) == int(port)) or (int(port) in hinted)
        if not port_ok:
            # Also scrape mitigation/description for explicit "port N" mentions.
            blob = f"{record.get('mitigation', '')} {record.get('description', '')}"
            if not re.search(rf"\bport\s*{port}\b", blob, re.IGNORECASE):
                continue

        fw = (firmware_version or "").strip()
        affected = str(record.get("affected_versions") or "")
        if fw and record.get("firmware_version") and str(record.get("firmware_version")) != fw:
            # Soft filter — still keep if affected_versions mentions the revision letter.
            if fw[0].upper() not in affected.upper() and fw not in affected:
                pass  # keep anyway for demo aggressiveness on family match

        hits.append(
            {
                "cve_id": cve_id,
                "severity": str(record.get("severity") or ""),
                "port": rec_port,
                "device_model": record.get("device_model"),
                "rationale": (
                    f"{cve_id} correlates to observed probe on port {port} "
                    f"for {device_model}"
                    + (f" (firmware {firmware_version})" if firmware_version else "")
                ),
            }
        )
    return hits


def primary_cve_for_port(device_model: str, port: int, *, firmware_version: str = "") -> str:
    hits = correlate_cves_for_port(device_model, port, firmware_version=firmware_version)
    if not hits:
        return ""
    device_slug = re.sub(r"[^a-z0-9]+", "_", (device_model or "").strip().lower())

    def _rank(hit: dict[str, Any]) -> tuple[int, int, int]:
        sev = str(hit.get("severity") or "").upper()
        sev_score = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev, 9)
        exact = 0 if hit.get("port") == port else 1
        rec_slug = re.sub(r"[^a-z0-9]+", "_", str(hit.get("device_model") or "").lower())
        # Prefer same device family over generic_embedded_linux.
        family = 0 if rec_slug == device_slug or ("intellivue" in device_slug and "intellivue" in rec_slug) else 1
        return (family, sev_score, exact)

    hits_sorted = sorted(hits, key=_rank)
    return str(hits_sorted[0]["cve_id"])
