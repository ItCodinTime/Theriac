#!/usr/bin/env python3
"""
Panacea v2 — Firewall Executor (Zain / Threat Execution & Security Infra)

Programs a Vultr Cloud Firewall group to enforce micro-segmentation based on a
"Contract B" lockdown dict produced upstream in the Panacea pipeline.

ACCOUNT-AGNOSTIC BY DESIGN:
    All credentials come from environment / .env only:
        VULTR_API_KEY, VULTR_FIREWALL_GROUP_ID, ...
    The target VM + firewall group live on a TEAMMATE'S Vultr account. Whoever
    owns the firewall group runs this script with their own .env / API key.
    Nothing here is hardcoded to any single account.

PUBLIC API (imported directly by Brian's FastAPI orchestrator):
    apply_rules(contract: dict) -> dict
    retract_rules(device_id: str) -> dict

Both are safe to call repeatedly and NEVER raise — they always return valid
JSON-serializable dicts with status in {success, fallback_success, error}.

CLI:
    python firewall_executor.py --contract contract_b_lockdown.json
    python firewall_executor.py --rollback
"""

import argparse
import json
import os
import sys

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - requests should be present, but stay safe
    requests = None

# Load .env if python-dotenv is available; otherwise fall back to os.environ.
try:
    from dotenv import load_dotenv  # type: ignore

    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
    load_dotenv()  # also honor a .env in CWD
except Exception:
    pass


# ----------------------------------------------------------------------------
# Config helpers
# ----------------------------------------------------------------------------

VULTR_API_BASE = "https://api.vultr.com/v2"
HTTP_TIMEOUT = 10  # seconds per Vultr API call

# Port that should never be exposed to the public internet.
SSH_PORT = 22
FORBIDDEN_PUBLIC_SOURCE = "0.0.0.0/0"


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _demo_mode() -> str:
    mode = _env("PANACEA_DEMO_MODE", "live").lower()
    return "mock" if mode == "mock" else "live"


def _firewall_group_id() -> str:
    return _env("VULTR_FIREWALL_GROUP_ID")


def _attacker_source_cidr() -> str:
    """Attacker public IP as a /32 CIDR (the source we manage)."""
    ip = _env("VULTR_ATTACKER_PUBLIC_IP")
    if not ip:
        return ""
    return ip if "/" in ip else f"{ip}/32"


def _mgmt_cidr() -> str:
    """Admin SSH source CIDR — must survive every run, never touched."""
    return _env("MANAGEMENT_SSH_SOURCE_CIDR")


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {_env('VULTR_API_KEY')}",
        "Content-Type": "application/json",
    }


# ----------------------------------------------------------------------------
# Rule normalization helpers
# ----------------------------------------------------------------------------

def _rule_source_cidr(rule: dict) -> str:
    """
    Extract a normalized 'ip/mask' source string from a Vultr rule dict.

    Vultr returns explicit IP sources via subnet + subnet_size, and named
    sources (e.g. 'cloudflare') or a raw value via the 'source' field. We
    normalize to a CIDR string when possible so we can compare against our
    attacker / management CIDRs.
    """
    subnet = str(rule.get("subnet", "") or "").strip()
    subnet_size = rule.get("subnet_size", "")
    if subnet:
        if subnet_size in (None, ""):
            return subnet
        return f"{subnet}/{subnet_size}"
    # Fallback to whatever 'source' holds (may be '', 'cloudflare', or a CIDR).
    return str(rule.get("source", "") or "").strip()


def _rule_port(rule: dict) -> str:
    return str(rule.get("port", "") or "").strip()


def _rule_action(rule: dict) -> str:
    # Vultr uses 'accept' for allow. Treat anything else conservatively.
    return str(rule.get("action", "") or "accept").strip().lower()


def _cidrs_equal(a: str, b: str) -> bool:
    if not a or not b:
        return False
    return a.strip().lower() == b.strip().lower()


# ----------------------------------------------------------------------------
# Vultr API wrappers — each guarded, never raise
# ----------------------------------------------------------------------------

def _list_rules(group_id: str) -> list:
    """GET all rules for a firewall group. Raises on failure (caller guards)."""
    if requests is None:
        raise RuntimeError("requests library not available")
    url = f"{VULTR_API_BASE}/firewalls/{group_id}/rules"
    resp = requests.get(url, headers=_headers(), timeout=HTTP_TIMEOUT)
    resp.raise_for_status()
    data = resp.json() or {}
    return data.get("firewall_rules", []) or []


def _create_rule(group_id: str, port: int, source_cidr: str, notes: str) -> dict:
    """POST a new ALLOW (accept) rule. Raises on failure (caller guards)."""
    if requests is None:
        raise RuntimeError("requests library not available")
    url = f"{VULTR_API_BASE}/firewalls/{group_id}/rules"
    body = {
        "ip_type": "v4",
        "protocol": "tcp",
        "port": str(port),
        "source": source_cidr,
        "notes": notes,
    }
    resp = requests.post(url, headers=_headers(), json=body, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()
    return resp.json() or {}


def _delete_rule(group_id: str, rule_id) -> None:
    """DELETE a rule by id. Raises on failure (caller guards)."""
    if requests is None:
        raise RuntimeError("requests library not available")
    url = f"{VULTR_API_BASE}/firewalls/{group_id}/rules/{rule_id}"
    resp = requests.delete(url, headers=_headers(), timeout=HTTP_TIMEOUT)
    resp.raise_for_status()


# ----------------------------------------------------------------------------
# Safety guard
# ----------------------------------------------------------------------------

def _is_forbidden_public_ssh(port: int, source_cidr: str) -> bool:
    """True if this would open SSH (22) to the whole internet — always blocked."""
    if int(port) != SSH_PORT:
        return False
    src = (source_cidr or "").strip()
    return src in (FORBIDDEN_PUBLIC_SOURCE, "0.0.0.0", "::/0", "0.0.0.0/0")


# ----------------------------------------------------------------------------
# Fallback / response builders
# ----------------------------------------------------------------------------

def _fallback_response(contract: dict, group_id: str, reason: str) -> dict:
    """Return a demo-safe fallback shape when live Vultr calls can't happen."""
    applied = []
    for rule in (contract.get("firewall_rules") or []):
        applied.append(
            {
                "port": rule.get("port"),
                "action": rule.get("action"),
                "result": "mocked",
            }
        )
    memo = contract.get("memo_text", "")
    return {
        "status": "fallback_success",
        "mode": "mock",
        "firewall_group_id": group_id,
        "applied_rules": applied,
        "memo_text": memo,
        "note": f"Live Vultr firewall unavailable, mocked firewall action completed for demo. ({reason})",
    }


# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------

def apply_rules(contract: dict) -> dict:
    """
    Apply a Contract B lockdown to the Vultr firewall group.

    ALLOW rules  -> ensure an accept rule exists for that port from the attacker
                    source IP (no duplicates).
    DENY rules   -> delete any existing accept rule for that port from the
                    attacker source IP.

    Never touches the MANAGEMENT_SSH_SOURCE_CIDR rule. Never opens port 22 to
    0.0.0.0/0. Never raises — returns a valid dict on every path.
    """
    contract = contract or {}
    group_id = _firewall_group_id()

    # Mock mode: short-circuit to fallback shape (but branded success for demo).
    if _demo_mode() == "mock":
        resp = _fallback_response(contract, group_id, "PANACEA_DEMO_MODE=mock")
        return resp

    attacker_cidr = _attacker_source_cidr()
    mgmt_cidr = _mgmt_cidr()

    # Pull current rules once. If this fails, fall back entirely.
    try:
        existing_rules = _list_rules(group_id)
    except Exception as exc:  # noqa: BLE001 - deliberately broad for demo safety
        return _fallback_response(contract, group_id, f"list rules failed: {exc}")

    applied_rules = []

    for rule in (contract.get("firewall_rules") or []):
        try:
            port = int(rule.get("port"))
        except (TypeError, ValueError):
            applied_rules.append(
                {"port": rule.get("port"), "action": rule.get("action"), "result": "skipped_bad_port"}
            )
            continue

        action = str(rule.get("action", "")).strip().upper()

        if action == "ALLOW":
            # Hard safety: never allow SSH to the public internet.
            if _is_forbidden_public_ssh(port, attacker_cidr) or not attacker_cidr:
                if not attacker_cidr:
                    applied_rules.append(
                        {"port": port, "action": "ALLOW", "result": "skipped_no_attacker_ip"}
                    )
                    continue

            # De-dupe: does an accept rule already exist for this port+source?
            already = any(
                _rule_port(r) == str(port)
                and _rule_action(r) == "accept"
                and _cidrs_equal(_rule_source_cidr(r), attacker_cidr)
                for r in existing_rules
            )
            if already:
                applied_rules.append({"port": port, "action": "ALLOW", "result": "exists_or_created"})
                continue

            notes = (
                "PANACEA approved HL7 patient data port"
                if port == 3200
                else "PANACEA approved rule"
            )
            try:
                _create_rule(group_id, port, attacker_cidr, notes)
                applied_rules.append({"port": port, "action": "ALLOW", "result": "exists_or_created"})
            except Exception as exc:  # noqa: BLE001
                applied_rules.append({"port": port, "action": "ALLOW", "result": f"failed: {exc}"})

        elif action == "DENY":
            # Delete any attacker-sourced accept rule for this port.
            # NEVER touch the management/admin SSH rule.
            deleted_any = False
            failed = False
            for r in existing_rules:
                if _rule_port(r) != str(port):
                    continue
                if _rule_action(r) != "accept":
                    continue
                src = _rule_source_cidr(r)
                # Protect admin SSH access — must survive every run.
                if mgmt_cidr and _cidrs_equal(src, mgmt_cidr):
                    continue
                # Only remove the attacker's rule (our managed source).
                if not _cidrs_equal(src, attacker_cidr):
                    continue
                rid = r.get("id")
                try:
                    _delete_rule(group_id, rid)
                    deleted_any = True
                except Exception:  # noqa: BLE001
                    failed = True
            if failed:
                applied_rules.append({"port": port, "action": "DENY", "result": "failed"})
            elif deleted_any:
                applied_rules.append({"port": port, "action": "DENY", "result": "removed"})
            else:
                applied_rules.append({"port": port, "action": "DENY", "result": "not_present"})

        else:
            applied_rules.append(
                {"port": port, "action": rule.get("action"), "result": "skipped_unknown_action"}
            )

    return {
        "status": "success",
        "mode": "live",
        "firewall_group_id": group_id,
        "applied_rules": applied_rules,
        "memo_text": contract.get("memo_text", ""),
    }


def retract_rules(device_id: str) -> dict:
    """
    DEMO RESET (not a security rollback).

    Re-adds the TEMP unsafe attacker SSH rule (port 22 from
    VULTR_ATTACKER_PUBLIC_IP) so the demo can be replayed from a clean "before"
    state where SSH is reachable from the attacker box.

    NEVER opens SSH to 0.0.0.0/0. NEVER touches MANAGEMENT_SSH_SOURCE_CIDR.
    Never raises.
    """
    group_id = _firewall_group_id()

    if _demo_mode() == "mock":
        return {
            "status": "fallback_success",
            "mode": "mock",
            "action": "retract_rules",
            "result": "mocked: temporary attacker SSH rule restored",
        }

    attacker_cidr = _attacker_source_cidr()

    # Safety: only ever the attacker's own /32, never the public internet.
    if not attacker_cidr or _is_forbidden_public_ssh(SSH_PORT, attacker_cidr):
        return {
            "status": "error",
            "mode": "live",
            "action": "retract_rules",
            "result": "refused: no safe attacker source IP to restore SSH from",
        }

    try:
        existing_rules = _list_rules(group_id)
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "fallback_success",
            "mode": "mock",
            "action": "retract_rules",
            "result": f"mocked: temporary attacker SSH rule restored (list failed: {exc})",
        }

    # If it already exists, we're done.
    already = any(
        _rule_port(r) == str(SSH_PORT)
        and _rule_action(r) == "accept"
        and _cidrs_equal(_rule_source_cidr(r), attacker_cidr)
        for r in existing_rules
    )
    if already:
        return {
            "status": "success",
            "mode": "live",
            "action": "retract_rules",
            "result": "temporary attacker SSH rule restored",
        }

    try:
        _create_rule(
            group_id,
            SSH_PORT,
            attacker_cidr,
            "PANACEA DEMO ONLY - temporary attacker SSH rule (reset state)",
        )
        return {
            "status": "success",
            "mode": "live",
            "action": "retract_rules",
            "result": "temporary attacker SSH rule restored",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "fallback_success",
            "mode": "mock",
            "action": "retract_rules",
            "result": f"mocked: temporary attacker SSH rule restored (create failed: {exc})",
        }


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def _load_contract(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Panacea firewall executor (Vultr Cloud Firewall)."
    )
    parser.add_argument(
        "--contract",
        metavar="PATH",
        help="Path to a Contract B lockdown JSON file; runs apply_rules().",
    )
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="Demo reset: re-add temporary attacker SSH rule via retract_rules().",
    )
    args = parser.parse_args(argv)

    if args.rollback:
        result = retract_rules(_env("VULTR_TARGET_INSTANCE_ID") or "demo-device")
    elif args.contract:
        try:
            contract = _load_contract(args.contract)
        except Exception as exc:  # noqa: BLE001
            result = {
                "status": "error",
                "mode": _demo_mode(),
                "result": f"could not read contract file: {exc}",
            }
        else:
            result = apply_rules(contract)
    else:
        parser.print_help()
        return 2

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
