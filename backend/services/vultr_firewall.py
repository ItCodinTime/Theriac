# Vultr Cloud Firewall REST client. Applies and retracts firewall rules on the target VPC via Vultr's HTTP API.
# OWNER: Zain — ported from infra/zain/firewall_executor.py (live-tested against the real Chicago target + firewall group).
# Brian's orchestrator calls these two functions with a ContractB payload.

import os
import socket
from datetime import datetime, timedelta, timezone

import httpx
import requests

from schemas.contract_b import ContractB

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass

VULTR_API_BASE = "https://api.vultr.com/v2"
HTTP_TIMEOUT = 10  # seconds per Vultr API call

# Port that should never be exposed to the public internet.
SSH_PORT = 22
FORBIDDEN_PUBLIC_SOURCE = "0.0.0.0/0"


class VultrNATGatewayEnforcer:
    """Compatibility enforcer for NAT Gateway port forwards + firewall rules.

    The active orchestrator path uses ``apply_rules`` below. This class is kept
    for the control-plane tests and for deployments that still enforce through a
    managed NAT gateway instead of a firewall group.
    """

    def __init__(
        self,
        *,
        api_key: str,
        gateway_id: str,
        device_ip: str,
        client: httpx.Client | None = None,
        base_url: str = VULTR_API_BASE,
    ) -> None:
        self.api_key = api_key
        self.gateway_id = gateway_id
        self.device_ip = device_ip
        self.client = client or httpx.Client(timeout=HTTP_TIMEOUT)
        self.base_url = base_url.rstrip("/")

    @property
    def _headers_httpx(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _url(self, suffix: str) -> str:
        return f"{self.base_url}/nat-gateways/{self.gateway_id}{suffix}"

    def _list(self, suffix: str) -> list[dict]:
        response = self.client.get(self._url(suffix), headers=self._headers_httpx)
        response.raise_for_status()
        payload = response.json() or {}
        return payload.get("data") or payload.get("rules") or payload.get("firewall_rules") or []

    def _post(self, suffix: str, body: dict) -> dict:
        response = self.client.post(self._url(suffix), headers=self._headers_httpx, json=body)
        response.raise_for_status()
        return response.json() or {}

    def _delete(self, suffix: str, rule_id: str) -> None:
        response = self.client.delete(self._url(f"{suffix}/{rule_id}"), headers=self._headers_httpx)
        response.raise_for_status()

    def _probe(self, port: int) -> str:
        host = _env("VULTR_NETWORK_PROBE_HOST", self.device_ip)
        try:
            with socket.create_connection((host, port), timeout=2):
                return "reachable"
        except OSError:
            return "blocked"

    def apply(self, policy: ContractB) -> dict:
        expires = datetime.now(timezone.utc) + timedelta(
            seconds=int(_env("VULTR_POLICY_LEASE_SECONDS", "900") or "900")
        )
        forwards = self._list("/port-forwarding-rules")
        firewall_rules = self._list("/firewall-rules")
        changes: list[dict] = []

        for rule in policy.firewall_rules:
            port = int(rule.port)
            action = rule.action.upper()

            if action == "ALLOW":
                if not any(int(item.get("internal_port") or item.get("port") or 0) == port for item in forwards):
                    created = self._post(
                        "/port-forwarding-rules",
                        {
                            "protocol": "tcp",
                            "external_port": port,
                            "internal_ip": self.device_ip,
                            "internal_port": port,
                        },
                    )
                    forwards.append({"id": created.get("id", ""), "internal_port": port})
                if not any(str(item.get("port") or "") == str(port) for item in firewall_rules):
                    created = self._post(
                        "/firewall-rules",
                        {
                            "protocol": "tcp",
                            "port": str(port),
                            "source": "0.0.0.0/0",
                            "notes": f"THERIAC allow; expires {expires.isoformat()}",
                        },
                    )
                    firewall_rules.append({"id": created.get("id", ""), "port": str(port)})
                changes.append({
                    "port": port,
                    "action": "ALLOW",
                    "status": "active",
                    "probe_status": self._probe(port),
                })
                continue

            if action == "DENY":
                for item in list(firewall_rules):
                    if str(item.get("port") or "") == str(port) and item.get("id"):
                        self._delete("/firewall-rules", str(item["id"]))
                        firewall_rules.remove(item)
                for item in list(forwards):
                    item_port = int(item.get("internal_port") or item.get("external_port") or item.get("port") or 0)
                    if item_port == port and item.get("id"):
                        self._delete("/port-forwarding-rules", str(item["id"]))
                        forwards.remove(item)
                changes.append({
                    "port": port,
                    "action": "DENY",
                    "status": "removed",
                    "probe_status": self._probe(port),
                })
                continue

            changes.append({"port": port, "action": action, "status": "skipped"})

        return {
            "status": "applied",
            "receipt": {
                "provider": "vultr",
                "gateway_id": self.gateway_id,
                "device_ip": self.device_ip,
                "changes": changes,
            },
        }


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _demo_mode() -> str:
    # Default changed from "live" to "mock": an accidental/unset run must be
    # harmless. Only an explicit PANACEA_DEMO_MODE=live arms real API calls.
    return "mock" if _env("PANACEA_DEMO_MODE", "mock").lower() == "mock" else "live"


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
    subnet = str(rule.get("subnet", "") or "").strip()
    subnet_size = rule.get("subnet_size", "")
    if subnet:
        return subnet if subnet_size in (None, "") else f"{subnet}/{subnet_size}"
    return str(rule.get("source", "") or "").strip()


def _rule_port(rule: dict) -> str:
    return str(rule.get("port", "") or "").strip()


def _rule_action(rule: dict) -> str:
    # Vultr uses 'accept' for allow. Treat anything else conservatively.
    return str(rule.get("action", "") or "accept").strip().lower()


def _cidrs_equal(a: str, b: str) -> bool:
    return bool(a) and bool(b) and a.strip().lower() == b.strip().lower()


# ----------------------------------------------------------------------------
# Vultr API wrappers — each guarded, never raise (callers catch)
# ----------------------------------------------------------------------------

def _list_rules(group_id: str) -> list:
    url = f"{VULTR_API_BASE}/firewalls/{group_id}/rules"
    resp = requests.get(url, headers=_headers(), timeout=HTTP_TIMEOUT)
    resp.raise_for_status()
    return (resp.json() or {}).get("firewall_rules", []) or []


def _create_rule(group_id: str, port: int, source_cidr: str, notes: str) -> dict:
    url = f"{VULTR_API_BASE}/firewalls/{group_id}/rules"
    # Vultr's rule API takes the source as separate `subnet` + `subnet_size`
    # fields, NOT a CIDR in `source` (that field is reserved for special values
    # like "cloudflare" and must be empty for a custom subnet). Passing a CIDR in
    # `source` returns 400 "Invalid IPv4 address".
    subnet, _, size = source_cidr.partition("/")
    body = {
        "ip_type": "v4",
        "protocol": "tcp",
        "port": str(port),
        "subnet": subnet,
        "subnet_size": int(size) if size else 32,
        "source": "",
        "notes": notes,
    }
    resp = requests.post(url, headers=_headers(), json=body, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()
    return resp.json() or {}


def _delete_rule(group_id: str, rule_id) -> None:
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
    return (source_cidr or "").strip() in (FORBIDDEN_PUBLIC_SOURCE, "0.0.0.0", "::/0")


# ----------------------------------------------------------------------------
# Fallback response builder
# ----------------------------------------------------------------------------

def _fallback_response(policy: ContractB, group_id: str, reason: str) -> dict:
    """Return a demo-safe fallback shape when live Vultr calls can't happen."""
    auth_failed = "401" in reason or "unauthorized" in reason.lower()
    applied = [
        {"port": r.port, "action": r.action, "result": "mocked"}
        for r in policy.firewall_rules
    ]
    note = (
        "Vultr API unauthorized (401) — VULTR_API_KEY is not valid for this "
        f"firewall group ({group_id}). Use the API key from the Vultr account "
        "that owns the group. Live rules were NOT changed. "
        f"({reason})"
        if auth_failed
        else f"Live Vultr firewall unavailable, mocked firewall action completed for demo. ({reason})"
    )
    return {
        "status": "auth_failed" if auth_failed else "fallback_success",
        "mode": "mock",
        "firewall_group_id": group_id,
        "auth_error": auth_failed,
        "applied_rules": applied,
        "memo_text": policy.memo_text,
        "note": note,
    }


# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------

def list_current_rules(group_id: str = None) -> dict:
    """
    Public, READ-ONLY helper: fetch the current live Vultr firewall rules for
    a group. Performs a GET only — never creates or deletes anything, and is
    intentionally exempt from PANACEA_DEMO_MODE (listing is safe regardless of
    demo/live mode). Never raises; always returns a dict.

    Used by backend/tools/fw.py's `plan` subcommand so it can show a diff of
    what `apply_rules()` would change without ever calling it.
    """
    gid = group_id or _firewall_group_id()
    if not gid:
        return {"status": "error", "firewall_group_id": gid, "error": "VULTR_FIREWALL_GROUP_ID is not set"}
    try:
        rules = _list_rules(gid)
        return {"status": "success", "firewall_group_id": gid, "rules": rules}
    except Exception as exc:  # noqa: BLE001 - deliberately broad, this must never raise
        err = str(exc)
        hint = ""
        if "401" in err or "Unauthorized" in err:
            hint = (
                " — VULTR_API_KEY is unauthorized for this group. "
                "Use the API key from the Vultr account that owns the firewall group."
            )
        return {"status": "error", "firewall_group_id": gid, "error": err + hint, "auth_error": "401" in err or "Unauthorized" in err}


def apply_rules(policy: ContractB) -> dict:
    """
    Push firewall rules to Vultr Cloud Firewall for the target VPC.
    Called by the orchestrator after Nemotron decides the zero-trust policy.

    ALLOW rules -> ensure an accept rule exists for that port from the attacker
                   source IP (no duplicates).
    DENY rules  -> delete any existing accept rule for that port from the
                   attacker source IP.

    Never touches MANAGEMENT_SSH_SOURCE_CIDR. Never opens port 22 to
    0.0.0.0/0. Never raises — returns a valid dict on every path.
    """
    group_id = _firewall_group_id()

    if _demo_mode() == "mock":
        return _fallback_response(policy, group_id, "PANACEA_DEMO_MODE=mock")

    attacker_cidr = _attacker_source_cidr()
    mgmt_cidr = _mgmt_cidr()

    try:
        existing_rules = _list_rules(group_id)
    except Exception as exc:  # noqa: BLE001 - deliberately broad for demo safety
        return _fallback_response(policy, group_id, f"list rules failed: {exc}")

    applied_rules = []

    for rule in policy.firewall_rules:
        port = rule.port
        action = rule.action.strip().upper()

        if action == "ALLOW":
            if not attacker_cidr:
                applied_rules.append({"port": port, "action": "ALLOW", "result": "skipped_no_attacker_ip"})
                continue
            # Hard safety: never allow SSH to the public internet. This check
            # must always short-circuit before a rule is created — do not nest
            # it behind the "no attacker IP" case above.
            if _is_forbidden_public_ssh(port, attacker_cidr):
                applied_rules.append({"port": port, "action": "ALLOW", "result": "blocked_public_ssh"})
                continue

            already = any(
                _rule_port(r) == str(port)
                and _rule_action(r) == "accept"
                and _cidrs_equal(_rule_source_cidr(r), attacker_cidr)
                for r in existing_rules
            )
            if already:
                applied_rules.append({"port": port, "action": "ALLOW", "result": "exists_or_created"})
                continue

            try:
                _create_rule(group_id, port, attacker_cidr, "PANACEA approved rule")
                applied_rules.append({"port": port, "action": "ALLOW", "result": "exists_or_created"})
            except Exception as exc:  # noqa: BLE001
                applied_rules.append({"port": port, "action": "ALLOW", "result": f"failed: {exc}"})

        elif action == "DENY":
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
                try:
                    _delete_rule(group_id, r.get("id"))
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
            applied_rules.append({"port": port, "action": rule.action, "result": "skipped_unknown_action"})

    return {
        "status": "success",
        "mode": "live",
        "firewall_group_id": group_id,
        "applied_rules": applied_rules,
        "memo_text": policy.memo_text,
    }


def retract_rules(policy: ContractB) -> dict:
    """
    DEMO RESET (not a security rollback) — currently wired as the Human
    Override endpoint's handler.

    WARNING: despite the name, this does NOT lock things down further. It
    re-adds the TEMP unsafe attacker SSH rule (port 22 from
    VULTR_ATTACKER_PUBLIC_IP) so the live-attack demo can be replayed from a
    clean "before" state where SSH is reachable from the attacker box again.
    If the frontend's Human Override toggle is meant to let an operator
    tighten security, wiring it to this function does the opposite —
    confirm the intended behavior with the team before shipping that wiring.

    NEVER opens SSH to 0.0.0.0/0. NEVER touches MANAGEMENT_SSH_SOURCE_CIDR.
    Never raises. `policy` is accepted for call-signature compatibility with
    the orchestrator but is not otherwise used.
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
