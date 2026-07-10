#!/usr/bin/env python3
"""
Panacea — scoped CLI wrapper around backend.services.vultr_firewall.

WHY THIS FILE EXISTS
    backend/services/vultr_firewall.py can make real, mutating calls against a
    live Vultr Cloud Firewall group (creating/deleting rules). Claude Code (or
    any operator) needs a way to plan/apply changes from the terminal without
    every invocation being either (a) unsafe-by-default or (b) requiring a
    manual confirmation prompt every single time, even for harmless mock runs.

    This wrapper gives three clearly-separated command shapes so a permission
    allowlist (see .claude/settings.local.json) can grant blanket approval to
    the two safe ones and leave the dangerous one always-prompting:

        fw.py plan  --contract PATH            read-only, never writes
        fw.py apply --contract PATH --mock     forced mock, never hits network
        fw.py apply --contract PATH            DANGEROUS: live if the shell's
                                                PANACEA_DEMO_MODE=live is set

    Only the first two are safe to blanket-allow. The third is intentionally
    left off the allowlist so it always prompts a human for confirmation.

USAGE
    python3 backend/tools/fw.py plan --contract infra/zain/contract_b_lockdown.json

    # Permission-safe mock invocation -- put --mock immediately after "apply"
    # (before any other flag). .claude/settings.local.json allowlists the
    # literal prefix "python3 backend/tools/fw.py apply --mock", so --mock
    # must appear there, not trailing after --contract, or the allowlisted
    # prefix won't match and Claude Code will (correctly) prompt instead.
    python3 backend/tools/fw.py apply --mock --contract infra/zain/contract_b_lockdown.json

    # Live, DANGEROUS -- not on the allowlist, always prompts:
    python3 backend/tools/fw.py apply --contract infra/zain/contract_b_lockdown.json
"""

import argparse
import json
import os
import sys

# backend/tools/fw.py sits one directory below backend/. The rest of the
# backend package imports things as `from services...` / `from schemas...`
# (see backend/main.py, backend/services/vultr_firewall.py) which only
# resolve correctly when backend/ itself is on sys.path -- mirror that here
# regardless of the caller's current working directory.
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from schemas.contract_b import ContractB  # noqa: E402
from services import vultr_firewall as vf  # noqa: E402


def _load_contract(path: str) -> ContractB:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return ContractB(**data)


# ----------------------------------------------------------------------------
# plan -- strictly read-only
# ----------------------------------------------------------------------------

def cmd_plan(args) -> int:
    """
    Read-only. Loads + validates the Contract B file, lists the CURRENT live
    firewall rules for VULTR_FIREWALL_GROUP_ID, and prints a diff-style
    summary of what `apply` would change. Performs ZERO writes: this function
    never calls vf._create_rule or vf._delete_rule, only vf.list_current_rules
    (a GET-only helper).

    Design choice on the "live GET" question: we DO make a live read-only GET
    call here (via vf.list_current_rules), rather than mocking it, because a
    GET against /firewalls/{id}/rules cannot mutate anything server-side --
    it's exactly as safe as `plan` is supposed to be, and mocking it would
    make the diff meaningless (it would just echo the contract back). If
    credentials aren't configured, this fails loudly and non-destructively
    (see the error handling below) rather than silently faking a result.
    """
    try:
        policy = _load_contract(args.contract)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: could not load/validate contract '{args.contract}': {exc}", file=sys.stderr)
        return 1

    group_id = vf._firewall_group_id()  # noqa: SLF001 - read-only accessor, same module family
    if not group_id:
        print(
            "ERROR: VULTR_FIREWALL_GROUP_ID is not set (check infra/zain/.env). "
            "Cannot list live rules; refusing to guess.",
            file=sys.stderr,
        )
        return 1

    listing = vf.list_current_rules(group_id)
    if listing.get("status") != "success":
        print(
            f"ERROR: could not list current live firewall rules for group '{group_id}': "
            f"{listing.get('error')}",
            file=sys.stderr,
        )
        print(
            "(Expected if VULTR_API_KEY / credentials are not configured in this environment. "
            "No rules were changed.)",
            file=sys.stderr,
        )
        return 1

    existing_rules = listing["rules"]
    attacker_cidr = vf._attacker_source_cidr()  # noqa: SLF001

    print(f"PLAN (read-only, no writes) for target_vpc_id={policy.target_vpc_id!r}")
    print(f"  firewall_group_id      : {group_id}")
    print(f"  attacker source CIDR   : {attacker_cidr or '(not set)'}")
    print(f"  existing live rules    : {len(existing_rules)}")
    print("-" * 72)

    for rule in policy.firewall_rules:
        port = rule.port
        action = rule.action

        currently_allowed = any(
            vf._rule_port(r) == str(port)  # noqa: SLF001
            and vf._rule_action(r) == "accept"  # noqa: SLF001
            and vf._cidrs_equal(vf._rule_source_cidr(r), attacker_cidr)  # noqa: SLF001
            for r in existing_rules
        )

        if action == "ALLOW":
            if not attacker_cidr:
                verdict = "SKIP -- no VULTR_ATTACKER_PUBLIC_IP configured"
            elif vf._is_forbidden_public_ssh(port, attacker_cidr):  # noqa: SLF001
                verdict = "BLOCKED by safety guard -- apply would refuse (public SSH)"
            elif currently_allowed:
                verdict = "no change (already ALLOW for attacker CIDR)"
            else:
                verdict = "WOULD ADD -- allow rule not currently present"
        else:  # DENY
            if currently_allowed:
                verdict = "WOULD REMOVE -- existing allow rule for attacker CIDR"
            else:
                verdict = "no change (already not allowed for attacker CIDR)"

        print(f"  port {port:>5}  {action:<5} -> {verdict}")

    print("-" * 72)
    print(f"Read-only summary complete. {len(existing_rules)} existing rule(s) fetched. No writes performed.")
    return 0


# ----------------------------------------------------------------------------
# apply -- the only subcommand that can write
# ----------------------------------------------------------------------------

def cmd_apply(args) -> int:
    """
    apply --mock : forces PANACEA_DEMO_MODE=mock before calling apply_rules(),
                   overriding whatever is in the shell environment. Always
                   safe, always mock, no network calls.

    apply         : calls apply_rules() using whatever PANACEA_DEMO_MODE is
                    actually set in the environment. Live (dangerous) only if
                    the operator explicitly exported PANACEA_DEMO_MODE=live
                    themselves. This path is NOT on the Claude Code permission
                    allowlist -- it must keep prompting for confirmation.
    """
    if args.mock:
        # Override before calling apply_rules(); vf._demo_mode() re-reads the
        # environment on every call, so setting this here is sufficient even
        # though `services.vultr_firewall` was already imported above.
        os.environ["PANACEA_DEMO_MODE"] = "mock"

    try:
        policy = _load_contract(args.contract)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({
            "status": "error",
            "result": f"could not load/validate contract '{args.contract}': {exc}",
        }, indent=2))
        return 1

    result = vf.apply_rules(policy)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in ("success", "fallback_success") else 1


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fw.py",
        description="Panacea scoped firewall CLI wrapper (Vultr Cloud Firewall).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    plan_p = sub.add_parser("plan", help="Read-only: show current live rules + what apply would change.")
    plan_p.add_argument("--contract", metavar="PATH", required=True, help="Path to a Contract B JSON file.")

    apply_p = sub.add_parser("apply", help="Apply a Contract B policy via apply_rules().")
    apply_p.add_argument("--contract", metavar="PATH", required=True, help="Path to a Contract B JSON file.")
    apply_p.add_argument(
        "--mock",
        action="store_true",
        help="Force PANACEA_DEMO_MODE=mock for this run only (safe, no live API calls).",
    )

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "plan":
        return cmd_plan(args)
    if args.command == "apply":
        return cmd_apply(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
