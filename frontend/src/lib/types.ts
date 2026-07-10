// Shared domain types for the Panacea Command Center.
// These mirror the backend API contracts defined in the project README so the
// UI can swap from simulated data to the real backend without shape changes.

/** A single allowed port entry from the device manual extraction. */
export interface AllowedPort {
  port: number;
  protocol: "TCP" | "UDP";
  reason: string;
}

/**
 * Contract A — Extraction Output pushed to the Vultr Vector Store.
 * Produced by the PDF parsing / extraction module.
 */
export interface ContractA {
  device_model: string;
  firmware_version: string;
  allowed_ports: AllowedPort[];
  source_doc_id: string;
}

/** A firewall rule action emitted by the agent decision step. */
export interface FirewallRule {
  port: number;
  action: "ALLOW" | "DENY";
}

/**
 * Contract B — Agent Decision sent to the Firewall API and rendered as the
 * formal "Incident Memo" in the Command Center UI.
 */
export interface ContractB {
  target_vpc_id: string;
  firewall_rules: FirewallRule[];
  confidence_score: number;
  cve_flagged: string | null;
  memo_text: string;
}

/** An incident memo enriched with UI metadata around a raw Contract B payload. */
export interface IncidentMemo extends ContractB {
  id: string;
  device_model: string;
  created_at: number;
}

/**
 * One entry from the backend's append-only audit log
 * (GET /api/v1/agent/audit). Every real autonomous decision is recorded.
 */
export interface AuditEntry {
  timestamp?: string;
  event?: string;
  lease_id?: string;
  operator_id?: string;
  device_model?: string;
  firmware_version?: string;
  source_doc_id?: string;
  confidence_score?: number;
  confidence_explanation?: string;
  reasoning_chars?: number;
  cve_flagged?: string;
  firewall_rules?: FirewallRule[];
  drift_alert?: string | null;
  evidence_key?: string;
  evidence_sha256?: string;
}

/** Operational status of a monitored medical device. */
export type DeviceStatus = "secure" | "monitoring" | "quarantined" | "override";

/** A monitored IIoT / medical device on the hospital network. */
export interface Device {
  id: string;
  model: string;
  vpc_id: string;
  firmware: string;
  status: DeviceStatus;
  bpm: number;
  ports: number[];
  last_seen: number;
  /** Firewall rules currently enforced on this device (from Contract B). */
  firewallRules?: FirewallRule[];
}

/** A single sample in a rolling ECG-style heartbeat waveform. */
export interface VitalSample {
  t: number;
  value: number;
}

/** Severity level of an agent reasoning log line. */
export type LogLevel = "info" | "success" | "warn" | "threat" | "system";

/** A streamed line of agent reasoning shown in the WebSocket terminal. */
export interface AgentLogLine {
  id: string;
  ts: number;
  level: LogLevel;
  step?: number;
  text: string;
  /**
   * Dim rendering for backend "reasoning" tokens (the model's thinking), vs
   * bright rendering for "content" tokens (the model's decisions).
   */
  dim?: boolean;
}

/** A point in the analytics time series for threats / port activity. */
export interface ThreatPoint {
  time: string;
  blocked: number;
  allowed: number;
  anomalies: number;
}

/** Aggregate KPIs rendered in the top stat row. */
export interface DashboardStats {
  devicesProtected: number;
  activeRules: number;
  threatsBlocked: number;
  avgConfidence: number;
  portsMonitored: number;
}
