# Panacea — Command Center (Next.js UI)

The frontend "Command Center" for **Panacea v2 — Zero-Trust Immune System for
Hospital Networks**. It renders live analytics, device heartbeat telemetry, the
autonomous agent reasoning stream (WebSocket terminal), Contract B incident
memos, and the Human Override control.

Built with Next.js (App Router) + TypeScript + Tailwind CSS v4, styled in a
glassmorphism aesthetic with `framer-motion` animations and `recharts` analytics.

## Running locally

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000.

> Node 18.18+ is required (this repo was built on Node 24 LTS). If you use
> `nvm`, run `nvm use --lts`.

## Data mode

The dashboard ships in **mock mode** and generates realistic telemetry locally,
so it runs with no backend. To point it at the real FastAPI service, copy
`.env.example` to `.env.local` and set:

```bash
NEXT_PUBLIC_USE_MOCK=false
NEXT_PUBLIC_API_URL=https://your-backend-host
NEXT_PUBLIC_WS_URL=wss://your-backend-host/ws/agent-stream
```

The only files that need to change to go live are the data hooks in
`src/hooks/` — every UI component is contract-shaped already
(`src/lib/types.ts`).

## Project structure

```
src/
  app/            # layout, page (dashboard composition), global glass styles
  components/dashboard/
    GlassCard      # reusable frosted-glass surface + panel header
    Header         # brand bar, live status pills, clock
    StatCard       # KPI analytics row
    HeartbeatMonitor # animated SVG ECG waveform (simulated vitals)
    ThreatChart    # allowed vs blocked network activity (recharts)
    AgentTerminal  # streaming agent reasoning (WebSocket terminal)
    IncidentMemo   # Contract B renderer (rules, confidence, CVE, memo)
    HumanOverride  # autonomous vs manual toggle
    DeviceTable    # monitored fleet + per-device policy retract
  hooks/           # useHeartbeat, useSimulatedStream (swap points for live data)
  lib/             # types (Contract A/B), config (env flags), simulator
```

## Deploying to Vercel

This app lives in the `frontend/` subdirectory of the monorepo, so when creating
the Vercel project:

1. Import the `Panecea` repo.
2. **Set Root Directory to `frontend`** (Project Settings → General → Root Directory).
3. Framework preset auto-detects as **Next.js**. No build overrides needed.
4. (Optional) add the `NEXT_PUBLIC_*` env vars above; defaults keep mock mode on.

Every pull request then gets an automatic **Preview Deployment** URL.
