#!/usr/bin/env python3
"""Live closed-loop demo: observe attack → SuperMemory → harden → Vultr firewall → re-probe.

Phases:
  1. BEFORE  — attack_simulator reachability snapshot
  2. OBSERVE — POST /api/v1/attacks/observe (ingest probes + CVE graph)
  3. HARDEN  — agent run (or deterministic harden) + apply_firewall_rule
  4. AFTER   — attack_simulator again; expect probed ports blocked for attacker

Usage:
  export THERIAC_API_URL=http://127.0.0.1:8001
  export PANACEA_DEMO_MODE=live   # real Vultr firewall; omit/mock for safe dry-run
  python backend/scripts/demo_live_firewall_loop.py
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parents[2]
BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

try:
    from dotenv import load_dotenv

    load_dotenv(BACKEND / ".env")
    load_dotenv(REPO / "infra" / "zain" / ".env")
except Exception:
    pass


def _run_simulator() -> dict:
    script = REPO / "infra" / "zain" / "attack_simulator.py"
    env = os.environ.copy()
    # Don't double-post from simulator during the BEFORE/AFTER snapshots.
    env.pop("THERIAC_API_URL", None)
    env.pop("NEXT_PUBLIC_API_URL", None)
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    stdout = (proc.stdout or "").strip()
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return {"raw": stdout, "stderr": proc.stderr, "returncode": proc.returncode}


def main() -> int:
    parser = argparse.ArgumentParser(description="Live attack→memory→firewall demo")
    parser.add_argument("--api", default=os.getenv("THERIAC_API_URL", "http://127.0.0.1:8001"))
    parser.add_argument("--device", default="Philips_IntelliVue")
    parser.add_argument("--ports", default="22,3200,24005", help="Comma-separated ports to observe")
    parser.add_argument("--skip-agent", action="store_true", help="Skip LLM agent; harden via history only")
    parser.add_argument("--live", action="store_true", help="Force PANACEA_DEMO_MODE=live for apply")
    args = parser.parse_args()
    api = args.api.rstrip("/")
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]

    if args.live:
        os.environ["PANACEA_DEMO_MODE"] = "live"

    print("=== PHASE 1: BEFORE (attacker reachability) ===")
    before = _run_simulator()
    print(json.dumps(before, indent=2))

    print("\n=== PHASE 2: OBSERVE → SuperMemory (attacks:* + CVE graph) ===")
    with httpx.Client(timeout=60) as client:
        observe = client.post(
            f"{api}/api/v1/attacks/observe",
            json={
                "device_model": args.device,
                "firmware_version": "L.0",
                "ports": ports,
                "protocol": "TCP",
                "run_immunity": True,
            },
        )
        observe.raise_for_status()
        observe_body = observe.json()
        print(json.dumps(observe_body, indent=2)[:2500])

        history = client.get(f"{api}/api/v1/attacks/{args.device}")
        history.raise_for_status()
        hist = history.json()
        print("\nAttack history harden_ports:", hist.get("harden_ports"))
        print("CVE graph:", hist.get("related_cves"))

        print("\n=== PHASE 3: HARDEN + ENFORCE ===")
        if args.skip_agent:
            # Deterministic path: build policy from history and apply via tool module.
            from schemas.contract_b import ContractB, FirewallRule
            from services.attack_memory import harden_policy_from_attacks, query_attack_history
            import asyncio
            from agent.tools.firewall import apply_firewall_rule

            summary = asyncio.run(query_attack_history(args.device))
            baseline = ContractB(
                target_vpc_id=os.getenv("VULTR_VPC_ID", "vpc-medical-01"),
                firewall_rules=[
                    FirewallRule(port=24105, action="ALLOW"),
                    FirewallRule(port=24005, action="ALLOW"),
                    FirewallRule(port=3200, action="ALLOW"),
                    FirewallRule(port=22, action="DENY"),
                ],
                confidence_score=90,
                cve_flagged="NONE",
                memo_text="live demo baseline",
            )
            hardened, notes = harden_policy_from_attacks(baseline, summary)
            print("Harden notes:", notes)
            apply_result = apply_firewall_rule(
                target_vpc_id=hardened.target_vpc_id,
                firewall_rules=[r.model_dump() for r in hardened.firewall_rules],
                confidence_score=hardened.confidence_score,
                cve_flagged=hardened.cve_flagged,
                memo_text="Live demo harden from attack memory",
            )
            print(apply_result)
            policy = hardened.model_dump()
        else:
            agent = client.post(
                f"{api}/api/v1/agent/run",
                json={"raw_pdf_text": "", "vpc_id": os.getenv("VULTR_VPC_ID", "vpc-medical-01")},
                timeout=240,
            )
            agent.raise_for_status()
            policy = agent.json()
            print("Rules:", policy.get("firewall_rules"))
            print("CVE:", policy.get("cve_flagged"))
            memo = policy.get("memo_text") or ""
            print("Memo excerpt:\n", memo[:900])

    print("\n=== PHASE 4: AFTER (attacker reachability) ===")
    after = _run_simulator()
    print(json.dumps(after, indent=2))

    print("\n=== VERDICT ===")
    b22 = before.get("port_22_reachable")
    a22 = after.get("port_22_reachable")
    print(f"port 22 reachable before={b22} after={a22}")
    harden = set(hist.get("harden_ports") or [])
    denied = {
        r["port"]
        for r in (policy.get("firewall_rules") or [])
        if r.get("action") == "DENY"
    }
    print(f"harden_ports={sorted(harden)} denied_in_policy={sorted(denied)}")
    if harden & denied:
        print("OK: attack memory hardened policy includes probed ports as DENY.")
        return 0
    print("WARN: harden ports not fully reflected in policy DENY set.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
