"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { config, endpoints, SAMPLE_MANUAL_TEXT } from "@/lib/config";
import { curateManualText, extractPdfText } from "@/lib/pdf";
import { tickDevice } from "@/lib/simulator";
import type {
  AgentLogLine,
  AuditEntry,
  ContractB,
  DashboardStats,
  Device,
  FirewallRule,
  IncidentMemo,
  LogLevel,
  ThreatPoint,
} from "@/lib/types";

const MAX_LOG_LINES = 400;
const MAX_MEMOS = 12;
const MAX_THREAT_POINTS = 40;

/** How the terminal/memos are currently sourced. */
export type DataMode = "mock" | "live" | "fallback";

export interface CommandCenterState {
  devices: Device[];
  logs: AgentLogLine[];
  memos: IncidentMemo[];
  threats: ThreatPoint[];
  stats: DashboardStats;
  auditEntries: AuditEntry[];
  auditLoading: boolean;
  autonomous: boolean;
  running: boolean;
  uploading: boolean;
  dataMode: DataMode;
  setAutonomous: (v: boolean) => void;
  runAgent: () => void;
  overrideDevice: (deviceId: string) => void;
  uploadManual: (file: File) => Promise<void>;
  refreshAudit: () => Promise<void>;
  explainMemo: (memo: IncidentMemo) => Promise<string>;
}

const lid = () => `log_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;

/** Authorization header for privileged endpoints, when an operator token is set. */
function authHeaders(base: Record<string, string> = {}): Record<string, string> {
  return config.operatorToken
    ? { ...base, Authorization: `Bearer ${config.operatorToken}` }
    : base;
}

const MARKER_RE = /^\s*\[[^\]]+\]/;

/**
 * Classify one complete line from the backend WebSocket stream.
 *
 * The backend emits two kinds of tokens:
 *   - reasoning: bracket "[STEP N]" progress markers + the model's raw
 *     chain-of-thought prose.
 *   - content:   a "[STEP 7 DONE]" marker + the final Contract B streamed as
 *     JSON, token-by-token.
 *
 * We surface the bracket markers as real milestone/error rows, fold the model's
 * prose into a collapsed "Reasoning" block, and drop the raw JSON decision
 * stream entirely (it's already rendered as an Incident Memo).
 */
function classifyStreamLine(line: string, type: string): AgentLogLine | null {
  const clean = line.trim();
  if (!clean) return null;
  const isMarker = MARKER_RE.test(clean);

  // Suppress the raw JSON decision firehose — redundant with the memo panel.
  if (!isMarker) {
    if (type === "content") return null;
    return { id: lid(), ts: Date.now(), level: "info", dim: true, text: clean };
  }

  const upper = clean.toUpperCase();
  let level: LogLevel;
  if (/ERROR|FAIL|EXCEPTION|TRACEBACK|REFUSED/.test(upper)) level = "threat";
  else if (/WARN|UNAVAILABLE|FALLBACK|DRIFT|TIMEOUT|OVERRIDE|\bHTTP\s*[45]\d\d|\b4\d\d\b|\b5\d\d\b/.test(upper))
    level = "warn";
  else if (/DONE|SEALED|ENFORCED|APPLIED|CONFIDENCE|READY/.test(upper)) level = "success";
  else level = "system";

  return { id: lid(), ts: Date.now(), level, dim: false, text: clean };
}

/** Map a backend Contract B payload to a UI incident memo. */
function memoFromContractB(data: ContractB, deviceModel: string): IncidentMemo {
  return {
    ...data,
    id: `memo_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`,
    device_model: deviceModel,
    created_at: Date.now(),
  };
}

/** Human-friendly device model + VPC slug derived from an uploaded filename. */
function manualIdentity(filename: string): { model: string; vpc: string } {
  const base = filename.replace(/\.[^.]+$/, "").trim();
  const model = base.replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim() || "Ingested Device";
  const slug =
    base.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 16) ||
    Math.random().toString(36).slice(2, 8);
  return { model, vpc: `vpc-${slug}` };
}

/** Build a new fleet Device from an ingested manual + its Contract B policy. */
function deviceFromManual(model: string, vpc: string, rules: FirewallRule[]): Device {
  const allow = rules.filter((r) => r.action === "ALLOW").map((r) => r.port);
  return {
    id: `dev_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
    model,
    vpc_id: vpc,
    firmware: "from manual",
    status: "secure",
    bpm: 74,
    ports: allow.length ? allow : rules.map((r) => r.port),
    last_seen: Date.now(),
    firewallRules: rules,
  };
}

/** Reflect an enforced Contract B policy onto the matching device. */
function applyEnforcement(devices: Device[], vpcId: string, rules: FirewallRule[]): Device[] {
  return devices.map((d) =>
    d.vpc_id === vpcId
      ? { ...d, firewallRules: rules, status: d.status === "override" ? "override" : "secure" }
      : d,
  );
}

/** A real network-activity point derived from an actual decision's rules. */
function threatPointFromRules(rules: FirewallRule[]): ThreatPoint {
  return {
    time: new Date().toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }),
    allowed: rules.filter((r) => r.action === "ALLOW").length,
    blocked: rules.filter((r) => r.action === "DENY").length,
    anomalies: 0,
  };
}

/**
 * Central data source for the Command Center.
 *
 * There is no simulated telemetry: the fleet starts empty and every device,
 * memo, reasoning line and audit entry comes from the live backend. Devices are
 * created by ingesting a real PDF manual. Anything that fails is written to the
 * terminal's error log rather than being faked. (The heartbeat waveform is the
 * only client-side visual — the backend does not stream device vitals.)
 */
export function useSimulatedStream(): CommandCenterState {
  const [devices, setDevices] = useState<Device[]>([]);
  const [logs, setLogs] = useState<AgentLogLine[]>([]);
  const [memos, setMemos] = useState<IncidentMemo[]>([]);
  const [threats, setThreats] = useState<ThreatPoint[]>([]);
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [autonomous, setAutonomous] = useState(true);
  const [running, setRunning] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [dataMode, setDataMode] = useState<DataMode>(config.useMock ? "mock" : "live");

  const devicesRef = useRef<Device[]>([]);
  const wsConnectedRef = useRef(false);
  const streamBufRef = useRef<{ reasoning: string; content: string }>({ reasoning: "", content: "" });

  useEffect(() => {
    devicesRef.current = devices;
  }, [devices]);

  // Boot line only — no seeded devices, memos or threat history.
  /* eslint-disable react-hooks/set-state-in-effect */
  useEffect(() => {
    setLogs([
      {
        id: "boot",
        ts: Date.now(),
        level: "system",
        text: config.useMock
          ? "Command Center offline :: set NEXT_PUBLIC_USE_MOCK=false and a backend URL to stream live agent activity."
          : "[BOOT] Command Center online :: connecting to live agent backend...",
      },
    ]);
  }, []);
  /* eslint-enable react-hooks/set-state-in-effect */

  const pushLogs = useCallback((incoming: AgentLogLine[]) => {
    setLogs((prev) => [...prev, ...incoming].slice(-MAX_LOG_LINES));
  }, []);

  const errorLog = useCallback(
    (text: string) => pushLogs([{ id: lid(), ts: Date.now(), level: "threat", dim: false, text }]),
    [pushLogs],
  );

  // ---- Live agent run: POST to the backend and render the returned Contract B.
  const runAgentLive = useCallback(async () => {
    setRunning(true);
    const target = devicesRef.current.find((d) => d.status !== "override");
    const vpc = target?.vpc_id ?? "vpc-medical-01";
    pushLogs([
      { id: lid(), ts: Date.now(), level: "system", dim: false, text: `[RUN] Agent run requested for ${vpc}...` },
    ]);
    try {
      const res = await fetch(endpoints.agentRun, {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ raw_pdf_text: SAMPLE_MANUAL_TEXT, vpc_id: vpc }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} from /agent/run`);
      const data = (await res.json()) as ContractB;
      const memo = memoFromContractB(data, target?.model ?? data.target_vpc_id);
      setMemos((m) => [memo, ...m].slice(0, MAX_MEMOS));
      setDevices((prev) => applyEnforcement(prev, data.target_vpc_id, data.firewall_rules));
      setThreats((prev) => [...prev, threatPointFromRules(data.firewall_rules)].slice(-MAX_THREAT_POINTS));
      pushLogs([
        {
          id: lid(),
          ts: Date.now(),
          level: "success",
          dim: false,
          text: `[DONE] Contract B received :: ${data.confidence_score}% confidence for ${data.target_vpc_id}.`,
        },
      ]);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "unknown error";
      errorLog(`[ERROR] Agent run failed :: ${msg}`);
    } finally {
      setRunning(false);
    }
  }, [pushLogs, errorLog]);

  const runAgent = useCallback(() => {
    if (running || uploading) return;
    if (config.useMock) {
      errorLog("[ERROR] No live backend configured — agent run unavailable in offline mode.");
      return;
    }
    runAgentLive();
  }, [running, uploading, runAgentLive, errorLog]);

  // ---- Manual ingestion: drop in a device-manual PDF. The agent reads it,
  // reasons over the WebSocket, returns Contract B, and the manual is
  // registered as a new device in the fleet with its enforced policy.
  const uploadManual = useCallback(
    async (file: File) => {
      if (uploading || running) return;
      if (config.useMock) {
        errorLog("[ERROR] No live backend configured — manual ingestion unavailable in offline mode.");
        return;
      }
      setUploading(true);
      setRunning(true);
      const { model, vpc } = manualIdentity(file.name);
      pushLogs([
        {
          id: lid(),
          ts: Date.now(),
          level: "system",
          dim: false,
          text: `[INGEST] Reading "${file.name}" in browser...`,
        },
      ]);

      // Register the analyzed policy as a device + memo, regardless of which
      // ingestion path produced the Contract B.
      const finalize = (data: ContractB) => {
        const targetVpc = data.target_vpc_id || vpc;
        const device = deviceFromManual(model, targetVpc, data.firewall_rules);
        setDevices((prev) => [device, ...prev.filter((d) => d.vpc_id !== targetVpc)]);
        setMemos((m) =>
          [memoFromContractB({ ...data, target_vpc_id: targetVpc }, model), ...m].slice(0, MAX_MEMOS),
        );
        setThreats((prev) => [...prev, threatPointFromRules(data.firewall_rules)].slice(-MAX_THREAT_POINTS));
        pushLogs([
          {
            id: lid(),
            ts: Date.now(),
            level: "success",
            dim: false,
            text: `[DONE] Manual analyzed :: ${model} enforced at ${data.confidence_score}% confidence.`,
          },
        ]);
      };

      try {
        // Extract the manual text in-browser (pdf.js) — far more reliable than
        // the backend's server-side parser — then send clean text to /agent/run.
        let text = "";
        try {
          text = await extractPdfText(file);
        } catch (exc) {
          const msg = exc instanceof Error ? exc.message : "unknown error";
          pushLogs([
            {
              id: lid(),
              ts: Date.now(),
              level: "warn",
              dim: false,
              text: `[INGEST WARN] In-browser PDF read failed :: ${msg}. Falling back to server-side extraction.`,
            },
          ]);
        }

        if (text.length >= 200) {
          // Never ship the whole manual — a huge payload overruns the model
          // context and times out the backend (502). Send a curated slice.
          const payload = curateManualText(text);
          const curatedNote =
            payload.length < text.length
              ? ` (sending ${payload.length.toLocaleString()} relevant chars)`
              : "";
          pushLogs([
            {
              id: lid(),
              ts: Date.now(),
              level: "system",
              dim: false,
              text: `[INGEST] Extracted ${text.length.toLocaleString()} chars from "${file.name}"${curatedNote} → analyzing ${vpc}`,
            },
          ]);
          const res = await fetch(endpoints.agentRun, {
            method: "POST",
            headers: authHeaders({ "Content-Type": "application/json" }),
            body: JSON.stringify({ raw_pdf_text: payload, vpc_id: vpc }),
          });
          if (!res.ok) throw new Error(`HTTP ${res.status} from /agent/run`);
          finalize((await res.json()) as ContractB);
        } else {
          // Too little text came out client-side — let the backend try the file.
          pushLogs([
            {
              id: lid(),
              ts: Date.now(),
              level: "warn",
              dim: false,
              text: `[INGEST WARN] Only ${text.length} chars extracted in-browser — sending raw PDF to backend instead.`,
            },
          ]);
          const form = new FormData();
          form.append("file", file);
          form.append("vpc_id", vpc);
          const res = await fetch(endpoints.manualsRun, {
            method: "POST",
            body: form,
            headers: authHeaders(),
          });
          if (!res.ok) throw new Error(`HTTP ${res.status} from /manuals/run`);
          finalize((await res.json()) as ContractB);
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : "unknown error";
        errorLog(`[ERROR] Manual ingestion failed :: ${msg}. The manual was not registered.`);
      } finally {
        setRunning(false);
        setUploading(false);
      }
    },
    [uploading, running, pushLogs, errorLog],
  );

  // ---- Live WebSocket: stream + classify agent reasoning into the terminal.
  useEffect(() => {
    if (config.useMock) return;

    let closed = false;
    let attempts = 0;
    let ws: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | null = null;

    const connect = () => {
      try {
        ws = new WebSocket(endpoints.agentStream);
      } catch {
        setDataMode("fallback");
        return;
      }

      ws.onopen = () => {
        attempts = 0;
        wsConnectedRef.current = true;
        setDataMode("live");
        pushLogs([
          { id: lid(), ts: Date.now(), level: "success", dim: false, text: "[BOOT] Live agent stream connected." },
        ]);
      };

      ws.onmessage = (ev) => {
        let text = "";
        let type = "reasoning";
        try {
          const msg = JSON.parse(ev.data);
          text = msg.text ?? msg.message ?? "";
          type = msg.type ?? "reasoning";
        } catch {
          text = typeof ev.data === "string" ? ev.data : "";
        }
        if (!text) return;

        // Buffer tokens and only emit complete, newline-delimited lines so the
        // token-by-token firehose becomes clean, classifiable rows.
        const key = type === "content" ? "content" : "reasoning";
        const combined = streamBufRef.current[key] + text;
        const segments = combined.split("\n");
        streamBufRef.current[key] = segments.pop() ?? "";
        const out: AgentLogLine[] = [];
        for (const seg of segments) {
          const entry = classifyStreamLine(seg, key);
          if (entry) out.push(entry);
        }
        if (out.length) pushLogs(out);
      };

      ws.onerror = () => {
        wsConnectedRef.current = false;
      };

      ws.onclose = () => {
        wsConnectedRef.current = false;
        if (closed) return;
        if (attempts < 4) {
          attempts += 1;
          retry = setTimeout(connect, 2000 * attempts);
        } else {
          setDataMode("fallback");
          errorLog("[ERROR] Live agent stream unavailable :: backend offline. Reasoning will not stream until it reconnects.");
        }
      };
    };

    connect();

    return () => {
      closed = true;
      if (retry) clearTimeout(retry);
      ws?.close();
    };
  }, [pushLogs, errorLog]);

  // Cosmetic device vitals for the heartbeat waveform (backend has no vitals).
  useEffect(() => {
    const vitals = setInterval(() => {
      setDevices((prev) => (prev.length ? prev.map(tickDevice) : prev));
    }, 2500);
    return () => clearInterval(vitals);
  }, []);

  // Human Override: retract the active policy for a device
  // (maps to DELETE /api/v1/policy/{device_id}).
  const overrideDevice = useCallback(
    async (deviceId: string) => {
      const device = devicesRef.current.find((d) => d.id === deviceId);
      const willOverride = device?.status !== "override";

      setDevices((prev) =>
        prev.map((d) =>
          d.id === deviceId
            ? {
                ...d,
                status: willOverride ? "override" : "secure",
                firewallRules: willOverride ? d.firewallRules : undefined,
              }
            : d,
        ),
      );

      pushLogs([
        {
          id: lid(),
          ts: Date.now(),
          level: "warn",
          dim: false,
          text: `[HUMAN OVERRIDE] Operator ${willOverride ? "retracting policy for" : "restoring"} ${device?.model ?? deviceId}.`,
        },
      ]);

      if (config.useMock || !willOverride) return;

      try {
        // The backend keys active policies by VPC id, not the client-side row id.
        const policyKey = device?.vpc_id ?? deviceId;
        const res = await fetch(endpoints.policy(policyKey), {
          method: "DELETE",
          headers: authHeaders(),
        });
        if (res.status === 404) {
          errorLog(`[HUMAN OVERRIDE WARN] Backend reports no active policy for '${policyKey}'.`);
        } else if (!res.ok) {
          errorLog(`[HUMAN OVERRIDE ERROR] Backend returned HTTP ${res.status}.`);
        }
      } catch {
        errorLog("[HUMAN OVERRIDE ERROR] Backend unreachable — override applied locally only.");
      }
    },
    [pushLogs, errorLog],
  );

  // ---- Real audit trail (GET /api/v1/agent/audit).
  const refreshAudit = useCallback(async () => {
    if (config.useMock) {
      setAuditEntries([]);
      return;
    }
    setAuditLoading(true);
    try {
      const res = await fetch(endpoints.audit(50), { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as { entries: AuditEntry[] };
      setAuditEntries(Array.isArray(data.entries) ? [...data.entries].reverse() : []);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "unknown error";
      errorLog(`[ERROR] Audit log fetch failed :: ${msg}`);
      setAuditEntries([]);
    } finally {
      setAuditLoading(false);
    }
  }, [errorLog]);

  // ---- Plain-English justification for a decision (POST /api/v1/agent/explain).
  const explainMemo = useCallback(async (memo: IncidentMemo): Promise<string> => {
    if (config.useMock) return "Explanations require a live backend connection.";
    const res = await fetch(endpoints.explain, {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        policy: {
          target_vpc_id: memo.target_vpc_id,
          firewall_rules: memo.firewall_rules,
          confidence_score: memo.confidence_score,
          cve_flagged: memo.cve_flagged ?? "NONE",
          memo_text: memo.memo_text,
        },
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} from /agent/explain`);
    const data = (await res.json()) as { explanation?: string };
    return data.explanation?.trim() || "No explanation returned.";
  }, []);

  const stats = useMemo<DashboardStats>(() => {
    const activeRules = memos.reduce((sum, m) => sum + m.firewall_rules.length, 0);
    const threatsBlocked = threats.reduce((sum, p) => sum + p.blocked, 0);
    const avgConfidence = memos.length
      ? Math.round(memos.reduce((s, m) => s + m.confidence_score, 0) / memos.length)
      : 0;
    const portsMonitored = new Set(devices.flatMap((d) => d.ports)).size;
    return {
      devicesProtected: devices.filter((d) => d.status !== "quarantined").length,
      activeRules,
      threatsBlocked,
      avgConfidence,
      portsMonitored,
    };
  }, [devices, memos, threats]);

  return {
    devices,
    logs,
    memos,
    threats,
    stats,
    auditEntries,
    auditLoading,
    autonomous,
    running,
    uploading,
    dataMode,
    setAutonomous,
    runAgent,
    overrideDevice,
    uploadManual,
    refreshAudit,
    explainMemo,
  };
}
