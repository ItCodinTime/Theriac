#!/usr/bin/env python3
"""Demo: replay an attack into Supermemory, then show the next scan would DENY that port.

Usage (backend running + Supermemory up):
  python backend/scripts/demo_attack_loop.py
  python backend/scripts/demo_attack_loop.py --port 24005 --api http://localhost:8000

Without a live API it still exercises ingest → query → harden against local Supermemory
(or prints the curl recipe if SUPERMEMORY is down).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

try:
    from dotenv import load_dotenv

    load_dotenv(BACKEND_ROOT / ".env")
except Exception:
    pass

import httpx

from schemas.attack_event import AttackEvent
from schemas.contract_b import ContractB, FirewallRule
from services.attack_memory import harden_policy_from_attacks, ingest_attack_event, query_attack_history


def _baseline_policy() -> ContractB:
    """Simulates a first-scan policy that ALLOWs the IntelliVue data ports."""
    return ContractB(
        target_vpc_id=os.getenv("VULTR_VPC_ID", "vpc-medical-01"),
        firewall_rules=[
            FirewallRule(port=24105, action="ALLOW"),
            FirewallRule(port=24005, action="ALLOW"),
            FirewallRule(port=22, action="DENY"),
        ],
        confidence_score=88,
        cve_flagged="CVE-2018-10597",
        memo_text="Baseline zero-trust policy before attack memory.",
    )


async def _via_api(api: str, device: str, port: int, source_ip: str) -> None:
    event = {
        "device_model": device,
        "attempted_port": port,
        "protocol": "UDP" if port in (24005, 24105) else "TCP",
        "source_ip": source_ip,
        "event_type": "unauthorized_lateral_probe",
        "severity": "high",
        "reason": f"Demo replay probe against port {port} from attacker VM",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        ingest = await client.post(f"{api.rstrip('/')}/api/v1/attacks", json=event)
        ingest.raise_for_status()
        print("[1] Ingested attack event:")
        print(json.dumps(ingest.json(), indent=2))

        history = await client.get(f"{api.rstrip('/')}/api/v1/attacks/{device}")
        history.raise_for_status()
        print("\n[2] Attack history recall:")
        print(json.dumps(history.json(), indent=2))

    from schemas.attack_event import AttackHistorySummary

    summary = AttackHistorySummary(**history.json())
    hardened, notes = harden_policy_from_attacks(_baseline_policy(), summary)
    print("\n[3] Next-scan policy after attack memory harden:")
    print(json.dumps(hardened.model_dump(), indent=2))
    print("\nHarden notes:")
    for note in notes:
        print(f"  - {note}")


async def _via_direct(device: str, port: int, source_ip: str) -> None:
    event = AttackEvent(
        device_model=device,
        attempted_port=port,
        protocol="UDP" if port in (24005, 24105) else "TCP",
        source_ip=source_ip,
        reason=f"Demo replay probe against port {port} from attacker VM",
    )
    stored = await ingest_attack_event(event)
    print("[1] Ingested attack event:")
    print(json.dumps(stored, indent=2))

    history = await query_attack_history(device)
    print("\n[2] Attack history recall:")
    print(history.model_dump_json(indent=2))

    hardened, notes = harden_policy_from_attacks(_baseline_policy(), history)
    print("\n[3] Next-scan policy after attack memory harden:")
    print(json.dumps(hardened.model_dump(), indent=2))
    print("\nHarden notes:")
    for note in notes:
        print(f"  - {note}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Demo the attack-memory closed loop")
    parser.add_argument("--api", default=os.getenv("THERIAC_API_URL", ""), help="Backend base URL")
    parser.add_argument("--device", default="Philips_IntelliVue")
    parser.add_argument("--port", type=int, default=24005, help="Port to 'attack' (default: manual-allowed 24005)")
    parser.add_argument(
        "--source-ip",
        default=os.getenv("VULTR_ATTACKER_PUBLIC_IP", "64.177.113.13"),
    )
    args = parser.parse_args()

    print(
        f"Replaying attack: {args.source_ip} → {args.device} port {args.port}\n"
        "Expect next scan to DENY that port citing attack memory.\n"
    )
    try:
        if args.api:
            asyncio.run(_via_api(args.api, args.device, args.port, args.source_ip))
        else:
            asyncio.run(_via_direct(args.device, args.port, args.source_ip))
    except Exception as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        print(
            "\nFallback curl recipe:\n"
            f'  curl -X POST "$API/api/v1/attacks" -H "Content-Type: application/json" '
            f'-d \'{{"device_model":"{args.device}","attempted_port":{args.port},'
            f'"source_ip":"{args.source_ip}","reason":"demo probe"}}\''
            "\n  # then re-run the agent scan / POST /api/v1/agent/run",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
