"use client";

import { useEffect, useState } from "react";
import { LayoutDashboard, TerminalSquare, Cpu, UploadCloud, ScrollText } from "lucide-react";
import { useSimulatedStream } from "@/hooks/useSimulatedStream";
import { Header } from "@/components/dashboard/Header";
import { TabNav, type TabDef } from "@/components/dashboard/TabNav";
import { StatsRow } from "@/components/dashboard/StatCard";
import { HeartbeatMonitor } from "@/components/dashboard/HeartbeatMonitor";
import { ThreatChart } from "@/components/dashboard/ThreatChart";
import { AgentTerminal } from "@/components/dashboard/AgentTerminal";
import { IncidentMemo } from "@/components/dashboard/IncidentMemo";
import { HumanOverride } from "@/components/dashboard/HumanOverride";
import { DeviceTable } from "@/components/dashboard/DeviceTable";
import { ManualUpload } from "@/components/dashboard/ManualUpload";
import { AuditTable } from "@/components/dashboard/AuditTable";

const TABS: TabDef[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "agent", label: "Live Agent", icon: TerminalSquare },
  { id: "ingest", label: "Ingest", icon: UploadCloud },
  { id: "fleet", label: "Devices", icon: Cpu },
  { id: "audit", label: "Audit", icon: ScrollText },
];

export default function CommandCenter() {
  const {
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
  } = useSimulatedStream();

  const [tab, setTab] = useState("overview");

  // Pull the real audit trail whenever the Audit tab is opened.
  useEffect(() => {
    if (tab === "audit") refreshAudit();
  }, [tab, refreshAudit]);

  return (
    <main className="mx-auto flex min-h-screen max-w-[1400px] flex-col gap-5 p-4 sm:p-6">
      <Header autonomous={autonomous} running={running} dataMode={dataMode} />

      <TabNav tabs={TABS} active={tab} onChange={setTab} />

      {tab === "overview" && (
        <div className="flex flex-col gap-5">
          <StatsRow stats={stats} />
          <section className="grid gap-5 lg:grid-cols-2">
            <HeartbeatMonitor devices={devices} />
            <ThreatChart data={threats} />
          </section>
        </div>
      )}

      {tab === "agent" && (
        <section className="grid h-[calc(100vh-15rem)] min-h-[460px] gap-5 lg:grid-cols-[1.35fr_1fr]">
          <AgentTerminal logs={logs} running={running} onRun={runAgent} />
          <IncidentMemo memos={memos} onExplain={explainMemo} />
        </section>
      )}

      {tab === "ingest" && (
        <div className="grid gap-5 lg:grid-cols-[1.35fr_1fr]">
          <ManualUpload
            uploading={uploading}
            onUpload={(file) => {
              uploadManual(file);
              setTab("agent");
            }}
          />
          <IncidentMemo memos={memos} onExplain={explainMemo} />
        </div>
      )}

      {tab === "fleet" && (
        <div className="flex flex-col gap-5">
          <HumanOverride autonomous={autonomous} onToggle={setAutonomous} />
          <DeviceTable devices={devices} onOverride={overrideDevice} />
        </div>
      )}

      {tab === "audit" && (
        <section className="h-[calc(100vh-15rem)] min-h-[460px]">
          <AuditTable entries={auditEntries} loading={auditLoading} onRefresh={refreshAudit} />
        </section>
      )}

      <footer className="mt-auto pt-2 text-center font-mono text-[11px] text-faint">
        Theriac v2 · Command Center · live agent reasoning, incident memos &amp; audit
        trail from the backend; device vitals are a client-side visualization
      </footer>
    </main>
  );
}
