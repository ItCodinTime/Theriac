#!/usr/bin/env python3
"""Cron-friendly attack observer loop.

One iteration:
  POST /api/v1/attacks/observe  (probe target + ingest + optional AHI)

Usage:
  THERIAC_API_URL=http://127.0.0.1:8001 python backend/scripts/run_attack_observer.py
  THERIAC_API_URL=... python backend/scripts/run_attack_observer.py --loop 30
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

import httpx


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default=os.getenv("THERIAC_API_URL", "http://127.0.0.1:8001"))
    parser.add_argument("--loop", type=int, default=0, help="Seconds between iterations (0=once)")
    parser.add_argument("--ports", default="22,3200,24005")
    parser.add_argument("--device", default="Philips_IntelliVue")
    args = parser.parse_args()
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    api = args.api.rstrip("/")
    body = {
        "device_model": args.device,
        "firmware_version": "L.0",
        "ports": ports,
        "protocol": "TCP",
        "run_immunity": True,
    }

    def once() -> None:
        with httpx.Client(timeout=60) as client:
            resp = client.post(f"{api}/api/v1/attacks/observe", json=body)
            resp.raise_for_status()
            print(json.dumps(resp.json(), indent=2)[:2000])

    if args.loop <= 0:
        once()
        return 0
    print(f"Observing every {args.loop}s → {api}/api/v1/attacks/observe (Ctrl+C to stop)")
    while True:
        try:
            once()
        except Exception as exc:  # noqa: BLE001
            print(f"observe failed: {exc}", file=sys.stderr)
        time.sleep(args.loop)


if __name__ == "__main__":
    raise SystemExit(main())
