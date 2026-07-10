"use client";

import { useMemo, useState } from "react";
import { HeartPulse, ChevronDown } from "lucide-react";
import { GlassCard, PanelHeader } from "./GlassCard";
import { useHeartbeat } from "@/hooks/useHeartbeat";
import { config } from "@/lib/config";
import type { Device } from "@/lib/types";

interface HeartbeatMonitorProps {
  devices: Device[];
}

export function HeartbeatMonitor({ devices }: HeartbeatMonitorProps) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const active = devices.find((d) => d.id === selectedId) ?? devices[0];
  const bpm = active?.bpm ?? 72;

  const tone =
    bpm > 120 ? "danger" : bpm > 105 ? "warn" : "good";

  return (
    <GlassCard delay={0.1} className="flex h-full flex-col overflow-hidden">
      <PanelHeader
        title="Device Heartbeat Telemetry"
        subtitle={config.useMock ? "Live vitals · simulated feed" : "Live device-twin telemetry"}
        icon={<HeartPulse className="h-4.5 w-4.5" />}
        action={
          devices.length > 0 && (
            <DeviceSelect
              devices={devices}
              value={active?.id ?? ""}
              onChange={setSelectedId}
            />
          )
        }
      />
      <div className="relative flex-1 p-3">
        <div className="grid-overlay recessed relative h-full min-h-44 overflow-hidden rounded-xl">
          {devices.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center text-center">
              <HeartPulse className="h-6 w-6 text-faint" />
              <p className="mt-3 text-sm text-muted">No devices monitored</p>
              <p className="section-label mt-1">Ingest a manual to add a device</p>
            </div>
          ) : (
            <>
          <Ecg bpm={bpm} tone={tone} />
          <div className="pointer-events-none absolute left-4 top-3">
            <div className="section-label">{active?.model ?? "—"}</div>
            <div className="mt-0.5 font-mono text-[10px] text-faint">
              {active?.vpc_id ?? ""}
            </div>
          </div>
          <div className="pointer-events-none absolute bottom-3 right-4 flex items-end gap-1">
            <span
              className={`text-3xl font-semibold tabular-nums ${
                tone === "danger"
                  ? "text-danger"
                  : tone === "warn"
                    ? "text-warn"
                    : "text-accent-2"
              }`}
            >
              {bpm}
            </span>
            <span className="section-label pb-1">BPM</span>
          </div>
            </>
          )}
        </div>
      </div>
    </GlassCard>
  );
}

function Ecg({ bpm, tone }: { bpm: number; tone: string }) {
  const samples = useHeartbeat({ bpm, window: 200, intervalMs: 40 });
  const stroke =
    tone === "danger" ? "#fb7185" : tone === "warn" ? "#f5b544" : "#3ecf8e";

  const points = useMemo(() => {
    const w = 1000;
    const h = 100;
    const n = samples.length;
    return samples
      .map((s, i) => {
        const x = (i / (n - 1)) * w;
        const y = h / 2 - s.value * (h * 0.42);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
  }, [samples]);

  return (
    <svg
      viewBox="0 0 1000 100"
      preserveAspectRatio="none"
      className="h-full w-full"
    >
      <defs>
        <linearGradient id="ecgFade" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor={stroke} stopOpacity="0" />
          <stop offset="20%" stopColor={stroke} stopOpacity="0.35" />
          <stop offset="100%" stopColor={stroke} stopOpacity="1" />
        </linearGradient>
        <filter id="glow">
          <feGaussianBlur stdDeviation="2.4" result="b" />
          <feMerge>
            <feMergeNode in="b" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
      <polyline
        points={points}
        fill="none"
        stroke="url(#ecgFade)"
        strokeWidth="2"
        strokeLinejoin="round"
        strokeLinecap="round"
        filter="url(#glow)"
      />
    </svg>
  );
}

function DeviceSelect({
  devices,
  value,
  onChange,
}: {
  devices: Device[];
  value: string;
  onChange: (id: string) => void;
}) {
  return (
    <div className="relative">
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="appearance-none rounded-lg bg-surface-2 py-1.5 pl-3 pr-8 text-xs text-muted ring-1 ring-hairline outline-none transition hover:text-foreground focus:ring-accent/50"
      >
        {devices.map((d) => (
          <option key={d.id} value={d.id} className="bg-surface text-foreground">
            {d.model}
          </option>
        ))}
      </select>
      <ChevronDown className="pointer-events-none absolute right-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
    </div>
  );
}
