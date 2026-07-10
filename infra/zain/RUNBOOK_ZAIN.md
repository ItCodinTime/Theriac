# RUNBOOK — Zain Module (Threat Execution & Security Infra)

Panacea v2 · RAISE Summit 2026 · Vultr track

## 1. Purpose

This module is the "muscle" of Panacea's zero-trust immune system. It does two
things:

1. **`firewall_executor.py`** — takes a "Contract B" lockdown decision produced
   upstream in the pipeline and enforces it by programming a **Vultr Cloud
   Firewall** group: allowing approved medical ports and denying lateral-pivot
   ports (e.g. SSH/22). It exposes importable functions so Brian's FastAPI
   orchestrator can call it directly.
2. **`attack_simulator.py`** — a *controlled* probe that proves the "before"
   (SSH reachable) vs "after" (SSH blocked) state for the demo. It only touches
   one fixed target on two fixed ports.

Everything is written for a live demo: it never crashes, and it degrades to a
mocked "fallback_success" response if Vultr is unreachable.

## 2. Required environment variables

Copy `.env.example` to `.env` and fill it in. Keys:

| Variable | Meaning |
|---|---|
| `VULTR_API_KEY` | API key for the account that **owns the firewall group**. |
| `VULTR_FIREWALL_GROUP_ID` | Vultr Cloud Firewall group to program. |
| `VULTR_TARGET_INSTANCE_ID` | Philips IntelliVue simulator instance id. |
| `VULTR_TARGET_PUBLIC_IP` | Target public IP (probed by the simulator). |
| `VULTR_TARGET_PRIVATE_IP` | Target private/VPC IP. |
| `VULTR_TARGET_REGION` | Target region. |
| `VULTR_ATTACKER_INSTANCE_ID` | Attacker VM instance id (my account). |
| `VULTR_ATTACKER_PUBLIC_IP` | Attacker public IP — the source we ALLOW/DENY. |
| `VULTR_ATTACKER_PRIVATE_IP` | Attacker private/VPC IP. |
| `MANAGEMENT_SSH_SOURCE_CIDR` | My admin SSH source CIDR — **never touched**. |
| `PANACEA_DEMO_MODE` | `live` (real Vultr calls) or `mock` (skip API). |

## 3. Cross-account architecture note (READ THIS)

The **target VM (Philips IntelliVue simulator) and its Vultr Cloud Firewall
group live on a teammate's Vultr account**, not mine. My attacker VM is on my
own account.

Because of this, `firewall_executor.py` is **fully account-agnostic**: it reads
`VULTR_API_KEY` and `VULTR_FIREWALL_GROUP_ID` from the environment / `.env`
only — nothing is hardcoded. **Whoever owns the firewall group runs the executor
with their own `.env` and their own API key.** I don't need their key, and they
don't need mine.

## 4. How to run

### Install deps

```bash
pip install requests python-dotenv
```

(`python-dotenv` is optional — without it the scripts read plain `os.environ`.)

### Attack simulator

```bash
python infra/zain/attack_simulator.py
```

Prints a JSON anomaly event including `port_22_reachable` and
`port_3200_reachable`. Run it **before** applying the contract (SSH should be
reachable) and **after** (SSH should be blocked).

### Firewall executor — apply mode

```bash
python infra/zain/firewall_executor.py --contract infra/zain/contract_b_lockdown.json
```

Calls `apply_rules()` and prints the resulting JSON.

### Firewall executor — rollback / demo reset mode

```bash
python infra/zain/firewall_executor.py --rollback
```

Calls `retract_rules()` and prints the resulting JSON. This is a **demo reset**,
not a security rollback: it re-adds the temporary attacker SSH rule so the demo
can be replayed from a clean "before" state.

## 5. Expected before / after firewall state

| State | Port 3200 (HL7) | Port 22 (SSH) from attacker | Admin SSH (`MANAGEMENT_SSH_SOURCE_CIDR`) |
|---|---|---|---|
| **Before** (`--rollback` applied) | (unchanged) | ALLOW (temp, unsafe) | ALLOW (always) |
| **After** (`--contract` applied) | ALLOW from attacker /32 | removed (DENY) | ALLOW (untouched) |

The attack simulator should report `port_22_reachable: true` before and
`false` after; `port_3200_reachable` stays `true`.

## 6. Safety constraints (enforced in code)

- **No real exploits.** The simulator does a single TCP connect per port — no
  payloads, no brute force.
- **No public scanning.** Only `VULTR_TARGET_PUBLIC_IP` and only ports 22 & 3200.
- **Never open port 22 to `0.0.0.0/0`.** The executor refuses this on every path.
- **Never delete the admin SSH rule.** Any rule whose source matches
  `MANAGEMENT_SSH_SOURCE_CIDR` is skipped during DENY processing.
- **Attacker-scoped changes only.** ALLOW/DENY operate on the attacker's own
  `/32`, not arbitrary sources.

## 7. Fallback behavior (Vultr unreachable)

If `PANACEA_DEMO_MODE=mock`, or if **any** Vultr API call fails or times out,
the executor catches it and returns a `fallback_success` response instead of
raising. The functions **never** throw to the caller — the orchestrator always
receives valid JSON. Each Vultr call is guarded individually, so one failed rule
does not abort the run; that rule is marked failed/mocked and processing
continues.

## 8. Integration note for Brian (orchestrator)

> My module exposes `apply_rules(contract: dict) -> dict` and
> `retract_rules(device_id: str) -> dict` in `firewall_executor.py`, importable
> directly into your orchestrator. Both are safe to call repeatedly and never
> raise — they always return `status: success | fallback_success | error`.
> I don't need your Vultr API key and you don't need mine; each teammate who
> owns Vultr infrastructure runs this against their own `.env`.

## 9. Display note for Oleh (UI)

> Display: `status`, `mode`, `firewall_rules`, `confidence_score`,
> `cve_flagged`, `memo_text`, `applied_rules`.
> If `status` is `fallback_success`, show:
> "Live Vultr firewall unavailable, mocked firewall action completed for demo."
