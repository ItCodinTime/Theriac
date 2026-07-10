// Deterministic-ish mock data engine for the Panacea Command Center.
//
// Everything here is fabricated but shaped exactly like the real backend
// contracts (see types.ts / README). Swap these generators for real API/WS
// data later without touching the UI components.

import type {
  AgentLogLine,
  ContractB,
  Device,
  IncidentMemo,
  LogLevel,
  ThreatPoint,
} from "./types";

let seq = 0;
const uid = (prefix = "id") => `${prefix}_${Date.now().toString(36)}_${(seq++).toString(36)}`;

const rand = (min: number, max: number) => Math.random() * (max - min) + min;
const randInt = (min: number, max: number) => Math.floor(rand(min, max + 1));
const pick = <T>(arr: readonly T[]): T => arr[Math.floor(Math.random() * arr.length)];

const DEVICE_MODELS = [
  { model: "Philips_IntelliVue", firmware: "B.01", ports: [24105, 24005] },
  { model: "GE_CARESCAPE_B650", firmware: "2.4", ports: [104, 2575] },
  { model: "Medtronic_Puritan_840", firmware: "4.07", ports: [502, 44818] },
  { model: "Draeger_Evita_V500", firmware: "A.11", ports: [3200, 20000] },
  { model: "Baxter_Sigma_Spectrum", firmware: "8.1", ports: [443, 8443] },
  { model: "Hillrom_Centrella", firmware: "1.9", ports: [161, 623] },
] as const;

const CVES = [
  "CVE-2023-30559",
  "CVE-2024-11053",
  "CVE-2023-45871",
  "CVE-2024-27114",
  null,
  null,
] as const;

/** Build the initial fleet of monitored devices. */
export function seedDevices(count = 6): Device[] {
  return Array.from({ length: count }, (_, i) => {
    const spec = DEVICE_MODELS[i % DEVICE_MODELS.length];
    const status = pick<Device["status"]>([
      "secure",
      "secure",
      "monitoring",
      "secure",
      "quarantined",
    ]);
    return {
      id: uid("dev"),
      model: spec.model,
      vpc_id: `vpc-medical-${String(i + 1).padStart(2, "0")}`,
      firmware: spec.firmware,
      status,
      bpm: randInt(58, 92),
      ports: [...spec.ports],
      last_seen: Date.now() - randInt(0, 40) * 1000,
    };
  });
}

/** Nudge a device's vitals/status slightly to simulate a live fleet. */
export function tickDevice(device: Device): Device {
  const drift = randInt(-3, 3);
  const bpm = Math.min(140, Math.max(48, device.bpm + drift));
  return {
    ...device,
    bpm,
    last_seen: Date.now(),
    status:
      device.status === "override"
        ? "override"
        : bpm > 120
          ? "quarantined"
          : bpm > 105
            ? "monitoring"
            : device.status === "quarantined"
              ? "monitoring"
              : "secure",
  };
}

/** One ECG waveform sample. `phase` is the running position [0, 1). */
export function ecgSample(phase: number, jitter = 0.04): number {
  // Piecewise approximation of a PQRST complex over a normalized cycle.
  const p = phase % 1;
  let v = 0;
  if (p < 0.12) v = Math.sin((p / 0.12) * Math.PI) * 0.12; // P wave
  else if (p < 0.18) v = -0.06; // PR segment dip
  else if (p < 0.22) v = -0.18; // Q
  else if (p < 0.26) v = 1.0; // R spike
  else if (p < 0.3) v = -0.35; // S
  else if (p < 0.5) v = Math.sin(((p - 0.3) / 0.2) * Math.PI) * 0.28; // T wave
  else v = 0;
  return v + rand(-jitter, jitter);
}

const STEP_LINES: { step: number; level: LogLevel; text: string }[] = [
  { step: 1, level: "system", text: "Ingest :: PDF manual pulled from Vultr Object Storage." },
  { step: 2, level: "info", text: "Extract :: Vultr Serverless Inference parsing device spec sheet..." },
  { step: 2, level: "info", text: "Extract :: Detected Philips Data Export Protocol on UDP port 24105." },
  { step: 2, level: "success", text: "Extract :: Firmware B.01 confirmed for Philips_IntelliVue." },
  { step: 3, level: "warn", text: "Cross-Check :: Querying Vultr Vector Store CVE memory for device + firmware..." },
  { step: 3, level: "threat", text: "Cross-Check :: Match found — lateral-movement risk on port 22." },
  { step: 4, level: "info", text: "Decide :: Generating zero-trust micro-segmentation policy." },
  { step: 4, level: "success", text: "Decide :: Confidence score computed at 96%." },
  { step: 5, level: "system", text: "Store :: Policy committed to Vultr Vector Store as canonical record." },
  { step: 6, level: "threat", text: "Enforce :: Device-twin intrusion hit policy — invoking Vultr NAT Gateway API." },
  { step: 6, level: "success", text: "Enforce :: Port 22 DENY rule applied to vpc-medical-01." },
  { step: 7, level: "success", text: "Report :: Incident Memo generated and streamed to Command Center." },
];

/** Yield the ordered 7-step reasoning trace for one agent run. */
export function agentRunTrace(): AgentLogLine[] {
  const base = Date.now();
  return STEP_LINES.map((l, i) => ({
    id: uid("log"),
    ts: base + i * 40,
    level: l.level,
    step: l.step,
    text: l.text,
  }));
}

const AMBIENT_LINES: { level: LogLevel; text: string }[] = [
  { level: "info", text: "Heartbeat :: fleet telemetry nominal across all VPCs." },
  { level: "system", text: "Watchdog :: WebSocket keepalive ACK received." },
  { level: "info", text: "Scan :: 0 unauthorized egress attempts in last window." },
  { level: "warn", text: "Anomaly :: elevated packet rate on port 2575, observing." },
  { level: "success", text: "Policy :: canonical record integrity verified." },
  { level: "threat", text: "Alert :: SSH probe blocked at network layer (port 22)." },
];

/** A single ambient log line for idle streaming between runs. */
export function ambientLine(): AgentLogLine {
  const l = pick(AMBIENT_LINES);
  return { id: uid("log"), ts: Date.now(), level: l.level, text: l.text };
}

/** Generate a fresh Contract B incident memo for a device. */
export function makeIncidentMemo(device?: Device): IncidentMemo {
  const spec = device
    ? { model: device.model, ports: device.ports, vpc: device.vpc_id }
    : { model: pick(DEVICE_MODELS).model, ports: [24105], vpc: "vpc-medical-01" };
  const confidence = randInt(88, 99);
  const cve = pick(CVES);
  const rules: ContractB["firewall_rules"] = [
    ...spec.ports.map((port) => ({ port, action: "ALLOW" as const })),
    { port: 22, action: "DENY" as const },
  ];
  return {
    id: uid("memo"),
    device_model: spec.model,
    created_at: Date.now(),
    target_vpc_id: spec.vpc,
    firewall_rules: rules,
    confidence_score: confidence,
    cve_flagged: cve,
    memo_text: cve
      ? `Blocked lateral pivot on Port 22. Allowed Port ${spec.ports[0]} per Vector ID: ${randInt(10000, 99999)}. ${cve} flagged during cross-check.`
      : `Blocked lateral pivot on Port 22. Allowed Port ${spec.ports[0]} per Vector ID: ${randInt(10000, 99999)}. No active CVEs matched.`,
  };
}

/** Seed the initial memo feed. */
export function seedMemos(devices: Device[], count = 3): IncidentMemo[] {
  return Array.from({ length: count }, (_, i) =>
    makeIncidentMemo(devices[i % devices.length]),
  ).map((m, i) => ({ ...m, created_at: Date.now() - (i + 1) * 90_000 }));
}

const fmtClock = (d: Date) =>
  `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}`;

/**
 * Organic-looking traffic for a given minute. Uses layered sine waves so
 * consecutive points connect into a smooth curve (instead of random noise),
 * plus a small jitter. `blockedBoost` lets real firewall DENY decisions spike
 * the blocked line so the chart reflects actual agent actions.
 */
function activityFor(minuteIndex: number, blockedBoost = 0) {
  const allowed =
    17 + Math.sin(minuteIndex / 4) * 7 + Math.sin(minuteIndex / 13) * 3 + rand(-1.2, 1.2);
  const blocked =
    1.6 + Math.sin(minuteIndex / 6) * 1.4 + Math.sin(minuteIndex / 17) * 0.8 + rand(-0.4, 0.4);
  return {
    allowed: Math.max(4, Math.round(allowed)),
    blocked: Math.max(0, Math.round(blocked)) + blockedBoost * 3,
    anomalies: 0,
  };
}

/** Build a rolling network-activity time series (last N minutes). */
export function seedThreatSeries(points = 24): ThreatPoint[] {
  const nowMin = Math.floor(Date.now() / 60_000);
  return Array.from({ length: points }, (_, i) => {
    const minuteIndex = nowMin - (points - 1 - i);
    return {
      time: fmtClock(new Date(minuteIndex * 60_000)),
      ...activityFor(minuteIndex),
    };
  });
}

/**
 * Next point to append to the series. Pass the number of DENY rules from a
 * fresh Contract B so a real lockdown visibly bumps the blocked line.
 */
export function nextThreatPoint(blockedBoost = 0): ThreatPoint {
  const nowMin = Math.floor(Date.now() / 60_000);
  return {
    time: fmtClock(new Date()),
    ...activityFor(nowMin, blockedBoost),
  };
}
