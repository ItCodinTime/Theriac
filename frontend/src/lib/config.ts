// Runtime configuration for the Command Center.
//
// The dashboard runs in "mock" mode by default so it works with no backend
// (great for Vercel previews). When NEXT_PUBLIC_USE_MOCK is "false", the data
// hook talks to the real FastAPI backend:
//   - REST (agent run + policy override) is proxied through Next.js rewrites
//     (see next.config.ts) so an HTTPS Vercel page can reach an http:// backend
//     without mixed-content / CORS problems.
//   - The WebSocket connects directly to NEXT_PUBLIC_WS_URL (cannot be proxied
//     on Vercel), so for the deployed HTTPS site it must be a wss:// URL.

export const config = {
  /** When true, all data is generated locally by the simulator. */
  useMock: process.env.NEXT_PUBLIC_USE_MOCK !== "false",

  /** REST base for the FastAPI backend (used by the server-side rewrite). */
  apiUrl: process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000",

  /** WebSocket endpoint that streams live agent reasoning tokens. */
  wsUrl:
    process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000/ws/agent-stream",

  /**
   * Optional operator bearer token for privileged endpoints (manual ingestion).
   * Only required when the backend runs in strict/OIDC mode; blank otherwise.
   */
  operatorToken: process.env.NEXT_PUBLIC_OPERATOR_TOKEN ?? "",
  /** Real Vultr VPC targeted by the demo agent. */
  vpcId: process.env.NEXT_PUBLIC_VPC_ID ?? "vpc-medical-01",
} as const;

/**
 * Backend routes.
 *
 * REST calls go through the same-origin `/backend/*` proxy (rewritten to
 * `config.apiUrl/*` server-side). The WebSocket is a direct connection.
 */
export const endpoints = {
  agentRun: "/backend/api/v1/agent/run",
  /** Multipart PDF manual ingestion (file + vpc_id) → streams + returns Contract B. */
  manualsRun: "/backend/api/v1/manuals/run",
  policy: (deviceId: string) => `/backend/api/v1/policy/${deviceId}`,
  /** Real, append-only decision history (GET, ?limit=). */
  audit: (limit = 50) => `/backend/api/v1/agent/audit?limit=${limit}`,
  /** Plain-English compliance justification for a Contract B (POST { policy }). */
  explain: "/backend/api/v1/agent/explain",
  agentStream: config.wsUrl,
} as const;

/**
 * Sample device-manual text sent as `raw_pdf_text` when triggering an agent
 * run from the UI (until a real uploaded PDF is wired in). Mirrors the Philips
 * IntelliVue example from the project README.
 */
// Empty string triggers the backend's deterministic demo path (Philips IntelliVue
// L.0, ports 24105/24005, CVE-2018-10597) — no LLM extraction lottery, no WARN.
export const SAMPLE_MANUAL_TEXT = "";
