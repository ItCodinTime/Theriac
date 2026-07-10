#!/usr/bin/env python3
"""
Panacea v2 — Controlled Attack Simulator (Zain / Threat Execution)

SAFETY SCOPE (hard limits, do not expand):
  * Tests ONLY the fixed target IP from env (VULTR_TARGET_PUBLIC_IP).
  * Tests EXACTLY two fixed ports: 22 (SSH) and 3200 (HL7 patient data).
  * Single TCP connect attempt per port with a short timeout.
  * No brute force, no payloads, no arbitrary IPs/ports, no loops, no scanning
    libraries. Just socket.create_connection() to prove reachability.

Prints one JSON anomaly event to stdout describing the SSH probe attempt.
"""

import json
import os
import socket
import sys

try:
    from dotenv import load_dotenv  # type: ignore

    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
    load_dotenv()
except Exception:
    pass


# Fixed, non-negotiable scope for the controlled test.
FIXED_PORTS = (22, 3200)
CONNECT_TIMEOUT = 3  # seconds — single attempt, short timeout


def _tcp_reachable(host: str, port: int, timeout: int = CONNECT_TIMEOUT) -> bool:
    """Single TCP connect attempt. True if the port accepts a connection."""
    if not host:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def run() -> dict:
    target_ip = (os.environ.get("VULTR_TARGET_PUBLIC_IP") or "").strip()

    reachability = {port: _tcp_reachable(target_ip, port) for port in FIXED_PORTS}

    event = {
        "event_type": "unauthorized_lateral_probe",
        "source": "panacea-attacker",
        "target": "panacea-philips-target",
        "target_ip": target_ip,
        "attempted_port": 22,
        "protocol": "TCP",
        "device_model": "Philips_IntelliVue",
        "firmware_version": "B.01",
        "severity": "high",
        "reason": "SSH probe against medical device not present in approved manual policy",
        "port_22_reachable": reachability[22],
        "port_3200_reachable": reachability[3200],
    }
    return event


def main() -> int:
    print(json.dumps(run(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
