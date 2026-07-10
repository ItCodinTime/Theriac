# Philips IntelliVue target VM (Mohamed — IIoT Target)

Panacea v2 · RAISE Summit 2026 · Vultr track

Real Vultr instance simulating the vulnerable Philips IntelliVue patient monitor for the live attack/defense demo.

## Purpose

This VM plays the "patient" in Panacea's demo: a stand-in for a real Philips
IntelliVue monitor, deliberately reachable the way an unmanaged hospital
device would be. It's what the rest of the pipeline actually acts on:

1. **Contract A** (manual sourcing) establishes what a real IntelliVue device
   needs — UDP 24105/24005, per the sourced manual — as the source-of-truth
   policy question.
2. **Contract B** (the firewall lockdown) is enforced directly against this
   VM's firewall group (`panacea-medical-lockdown`) by the `vultr_firewall.py`
   executor.
3. **The live demo** proves the lockdown is real against *this* box: Zain's
   attacker VM can reach the intentionally-open demo port but is blocked on
   SSH — see "Port 22 (SSH) lockdown state" below.

**Known simplification (READ THIS):** this VM's simulated service is a
placeholder TCP responder on port 3200/"HL7" (`hl7_listener.py`), not the
real UDP 24105/24005 protocol referenced elsewhere in the docs. The demo's
firewall lockdown logic and live attack/defense flow are validated against
port 3200, not 24105. Not a bug — just don't assume the two ports are the
same.

## Current state — ACTIVE TARGET (Chicago)

| Item | Value |
|---|---|
| Provider | Vultr Cloud Compute |
| Region | Chicago (`ord`) |
| Plan | `vc2-1c-1gb` ($5/mo, billed hourly — negligible cost for the event) |
| OS | Ubuntu 24.04 LTS |
| Instance ID | `efac5ff6-8cb8-4b2c-b522-f320e8573ea3` |
| Public IP | `64.177.118.214` |
| VPC | `panacea-medical-vpc` (`71c87a0e-97fd-4e31-9f65-85d520f428a4`), subnet `10.100.0.0/24`, region `ord` — matches the `target_vpc_id` field referenced in Contract B (e.g. `"vpc-medical-01"`) |
| VPC internal IP | `10.100.0.3` |
| Firewall group | `panacea-medical-lockdown` (`de7a05fc-ecdf-4645-92d2-989b02951598`) — details below |
| Port 3200 (HL7) | Open to everyone (`0.0.0.0/0`) at the cloud firewall and at the OS-level `ufw` firewall — details below |
| Port 22 (SSH) | Locked down — cloud firewall allows only the admin CIDR (`MANAGEMENT_SSH_SOURCE_CIDR` in `infra/zain/.env`, gitignored); attacker VM denied — details below |

### Firewall group

`panacea-medical-lockdown` (`de7a05fc-ecdf-4645-92d2-989b02951598`) is the
firewall group attached to the Chicago target instance
(`infra/zain/.env`, `VULTR_FIREWALL_GROUP_ID`). Note: an older group
`panacea-target-fw` (`b57ae685-a98b-44e2-a867-60270e9647de`) also exists on
this account but is not attached here — ignore it if you see it in the Vultr
console.

### Port 3200 (HL7 listener) details

A real Python TCP listener (`hl7_listener.py`) is running as a systemd
service, responding with a placeholder HL7-style ACK.

Port 3200 is open end-to-end: at the Vultr cloud firewall (`0.0.0.0/0`) and
at the box's own OS-level `ufw` firewall (`ufw allow 3200/tcp`).

### Port 22 (SSH) lockdown state

The Vultr cloud firewall allows port 22 only from the admin CIDR
(`MANAGEMENT_SSH_SOURCE_CIDR`, not committed anywhere in this repo). Zain's
attacker VM (`64.177.113.13/32`) is explicitly denied on port 22
(`infra/zain/contract_b_lockdown.json` shows `{"port": 22, "action": "DENY"}`
for the attacker's rule).

This is the intended demo behavior for `panacea-medical-lockdown`: the
attacker VM times out on port 22 (no SSH access) while still being able to
reach port 3200.

## Team context

Not Mohamed's action items — noted here for reference.

- **Zain** (attacker VM / Python firewall execution scripts owner): attacker VM is live at `64.177.113.13` (root SSH access). This IP is explicitly denied on port 22 by `panacea-medical-lockdown` — it can reach port 3200, but has no SSH access to the target.
- **Brian** (backend/orchestrator, presumably FastAPI): service reported running at `45.76.26.39`. Not attached to the VPC and no action taken here — flagging in case private networking between backend and target VPC becomes relevant later.

## Files in this directory

- `hl7_listener.py` — the trivial placeholder TCP listener bound to port 3200. Not real HL7 protocol logic — just enough to be a real, alive service so the firewall's "allow 3200" rule has something real behind it. Deployed at `/root/hl7_listener.py` on the Chicago target VM.
- `hl7-listener.service` — systemd unit running the listener, auto-restarts, survives reboots. Installed at `/etc/systemd/system/hl7-listener.service`, enabled via `systemctl enable --now hl7-listener.service`.

## Redeploying `hl7_listener.py`

The running service on the box does **not** auto-update when this file
changes in the repo — it has to be pushed manually:

```bash
# 1. Copy the updated listener to the box (the systemd unit itself is
#    unchanged, so no need to reinstall it, just overwrite the script)
scp -i ~/.ssh/panacea_target infra/philips-target/hl7_listener.py \
    root@64.177.118.214:/root/hl7_listener.py

# 2. Restart the service and confirm it came back up clean
ssh -i ~/.ssh/panacea_target root@64.177.118.214 \
    "systemctl restart hl7-listener.service && systemctl status hl7-listener.service --no-pager"
```

Expected: `Active: active (running)`, with a recent `Listening on
0.0.0.0:3200` line in the journal (`journalctl -u hl7-listener.service -n 5`).

Verify it actually took effect from a machine that can reach the target (the
admin CIDR or attacker CIDR — a generic sandbox/dev box usually can't, since
neither CIDR matches its egress IP):

```bash
nc -zv 64.177.118.214 3200   # should connect
nc -zv 64.177.118.214 22     # should time out unless you're on the admin CIDR
```

**TODO before demo:** redeploy `hl7_listener.py` (steps above) — the box is
currently running an older version without the disconnect-handling fix.

## For Zain (attacker VM owner)

> Target IP: `64.177.118.214` (Chicago — the real target; do not use the old
> `45.32.146.113` Paris IP). Port 22 from your attacker VM's IP
> (`64.177.113.13/32`) is explicitly denied at the Vultr cloud firewall
> (`panacea-medical-lockdown`) — a connection timeout on 22 is the correct,
> intended result of the demo, not a bug. Port 3200 is reachable from your VM;
> `ufw` on the target box has an explicit `allow 3200/tcp` rule, so 3200
> connectivity should be reliable.

## Re-provisioning notes

- SSH key pair for admin access is `panacea-target-key` (registered on the Vultr account, ID `e766aa16-af8a-4436-9aaf-2892ea5bac9c`), keypair not stored in this repo (local copy at `~/.ssh/panacea_target` on Mohamed's machine).
- Firewall group ID, instance IDs, and VPC ID are tracked outside this repo (Vultr Console) since they're account-specific, not portable config; this README mirrors them for team visibility only.

### If this VM needs to be recreated from scratch

Steps, assuming the VPC (`panacea-medical-vpc`) and firewall group
(`panacea-medical-lockdown`) already exist and you just need a new instance
attached to them (requires `vultr-cli`, configured with an API key that has
this Vultr account's access — see `infra/zain/.env`, gitignored):

```bash
# 1. Create the instance (Ubuntu 24.04 LTS x64 = os id 2284; check with
#    `vultr-cli os list`; adjust --label/--region if deploying elsewhere)
vultr-cli instance create \
  --region="ord" \
  --plan="vc2-1c-1gb" \
  --os=2284 \
  --label="panacea-philips-target-chicago" \
  --vpc-ids="71c87a0e-97fd-4e31-9f65-85d520f428a4" \
  --ssh-keys="e766aa16-af8a-4436-9aaf-2892ea5bac9c" \
  --firewall-group="de7a05fc-ecdf-4645-92d2-989b02951598"

# 2. Once it's up, note its new public IP (vultr-cli instance list), then
#    deploy the listener the same way as a normal redeploy (see above):
scp -i ~/.ssh/panacea_target infra/philips-target/hl7_listener.py \
    root@<NEW_PUBLIC_IP>:/root/hl7_listener.py
scp -i ~/.ssh/panacea_target infra/philips-target/hl7-listener.service \
    root@<NEW_PUBLIC_IP>:/etc/systemd/system/hl7-listener.service
ssh -i ~/.ssh/panacea_target root@<NEW_PUBLIC_IP> \
    "systemctl daemon-reload && systemctl enable --now hl7-listener.service && \
     ufw allow 22/tcp && ufw allow 3200/tcp && ufw --force enable && \
     systemctl status hl7-listener.service --no-pager"
```

If the firewall group itself also needs recreating from zero (not just the
VM), that's a separate, rarer case — use `vultr-cli firewall group create`
plus `vultr-cli firewall rule create` for each rule described in "Current
state" above (admin CIDR on 22, attacker CIDR on 3200). See
`infra/zain/RUNBOOK_ZAIN.md` §6 ("Safety constraints") for what those rules
must guarantee — don't duplicate that reasoning here, just point to it.

**Update this README afterward** with the new instance ID / public IP —
everything above (`Current state` table, "For Zain" note) currently points
at the live Chicago instance and will go stale the moment it's replaced.
