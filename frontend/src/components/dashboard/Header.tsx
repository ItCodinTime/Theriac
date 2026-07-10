"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Activity, Wifi, WifiOff, FlaskConical } from "lucide-react";
import type { DataMode } from "@/hooks/useSimulatedStream";

interface HeaderProps {
  autonomous: boolean;
  running: boolean;
  dataMode: DataMode;
}

/** Top command bar: brand wordmark, live system status and clock. */
export function Header({ autonomous, running, dataMode }: HeaderProps) {
  const [now, setNow] = useState<string>("");

  useEffect(() => {
    const fmt = () =>
      new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
    const initial = setTimeout(() => setNow(fmt()), 0);
    const id = setInterval(() => setNow(fmt()), 1000);
    return () => {
      clearTimeout(initial);
      clearInterval(id);
    };
  }, []);

  return (
    <motion.header
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
      className="spotlight glass flex flex-wrap items-center justify-between gap-4 rounded-[14px] px-5 py-4"
    >
      <div className="flex items-center gap-3.5">
        <div className="grid h-10 w-10 place-items-center rounded-lg bg-primary text-white shadow-[0_0_24px_-6px_rgba(0,7,205,0.9)]">
          <span className="font-mono text-lg font-semibold leading-none">P</span>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-[17px] font-semibold tracking-tight text-foreground">
              Theriac
            </h1>
            <span className="section-label rounded bg-surface-2 px-1.5 py-0.5 ring-1 ring-hairline">
              v2
            </span>
          </div>
          <p className="section-label mt-0.5">
            Zero-Trust Immune System · Command Center
          </p>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <StatusPill
          label={
            dataMode === "live"
              ? "Live Backend"
              : dataMode === "fallback"
                ? "Backend Offline"
                : "Simulated"
          }
          tone={dataMode === "live" ? "good" : dataMode === "fallback" ? "warn" : "idle"}
          icon={
            dataMode === "live" ? (
              <Wifi className="h-3.5 w-3.5" />
            ) : dataMode === "fallback" ? (
              <WifiOff className="h-3.5 w-3.5" />
            ) : (
              <FlaskConical className="h-3.5 w-3.5" />
            )
          }
        />
        <StatusPill
          label={autonomous ? "Autonomous" : "Manual"}
          tone={autonomous ? "good" : "warn"}
        />
        <StatusPill
          label={running ? "Running" : "Standby"}
          tone={running ? "active" : "idle"}
          icon={<Activity className="h-3.5 w-3.5" />}
        />
        <div className="hidden font-mono text-xs tabular-nums text-faint sm:block">
          {now}
        </div>
      </div>
    </motion.header>
  );
}

function StatusPill({
  label,
  tone,
  icon,
}: {
  label: string;
  tone: "good" | "warn" | "active" | "idle";
  icon?: React.ReactNode;
}) {
  const tones: Record<string, string> = {
    good: "text-accent-2",
    warn: "text-warn",
    active: "text-accent",
    idle: "text-muted",
  };
  const dot: Record<string, string> = {
    good: "bg-accent-2 pulse-dot",
    warn: "bg-warn",
    active: "bg-accent pulse-dot",
    idle: "bg-faint",
  };
  return (
    <div className="flex items-center gap-2 rounded-md bg-surface-2 px-2.5 py-1.5 text-xs font-medium ring-1 ring-hairline">
      <span className={`h-1.5 w-1.5 rounded-full ${dot[tone]}`} />
      {icon && <span className={tones[tone]}>{icon}</span>}
      <span className={tones[tone]}>{label}</span>
    </div>
  );
}
