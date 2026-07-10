"use client";

import { motion } from "framer-motion";
import { Cpu, Power } from "lucide-react";
import { GlassCard, PanelHeader } from "./GlassCard";
import type { Device, DeviceStatus } from "@/lib/types";

interface DeviceTableProps {
  devices: Device[];
  onOverride: (deviceId: string) => void;
}

const STATUS_META: Record<DeviceStatus, { label: string; dot: string; text: string }> = {
  secure: { label: "Secure", dot: "bg-accent-2", text: "text-accent-2" },
  monitoring: { label: "Monitoring", dot: "bg-accent", text: "text-accent" },
  quarantined: { label: "Quarantined", dot: "bg-danger", text: "text-danger" },
  override: { label: "Overridden", dot: "bg-warn", text: "text-warn" },
};

export function DeviceTable({ devices, onOverride }: DeviceTableProps) {
  return (
    <GlassCard delay={0.2} className="flex h-full flex-col overflow-hidden">
      <PanelHeader
        title="Monitored Devices"
        subtitle={`${devices.length} medical endpoints on network`}
        icon={<Cpu className="h-4.5 w-4.5" />}
      />
      <div className="slim-scroll flex-1 overflow-x-auto px-2 pb-2">
        {devices.length === 0 ? (
          <div className="flex min-h-40 flex-col items-center justify-center py-10 text-center">
            <Cpu className="h-6 w-6 text-faint" />
            <p className="mt-3 text-sm text-muted">No devices on the network</p>
            <p className="section-label mt-1">Ingest a device manual to register one</p>
          </div>
        ) : (
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="text-left">
              <th className="section-label px-3 py-2.5">Device</th>
              <th className="section-label px-3 py-2.5">VPC</th>
              <th className="section-label px-3 py-2.5">Ports / Firewall</th>
              <th className="section-label px-3 py-2.5">Status</th>
              <th className="section-label px-3 py-2.5 text-right">Control</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => {
              const meta = STATUS_META[d.status];
              return (
                <motion.tr
                  key={d.id}
                  layout
                  className="border-t border-hairline transition hover:bg-surface-2"
                >
                  <td className="px-3 py-2.5">
                    <div className="font-medium text-foreground">{d.model}</div>
                    <div className="font-mono text-[10px] text-faint">
                      fw {d.firmware}
                    </div>
                  </td>
                  <td className="px-3 py-2.5 font-mono text-xs text-muted">
                    {d.vpc_id}
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {d.firewallRules?.length
                        ? d.firewallRules.map((r, i) => (
                            <span
                              key={`${r.port}-${i}`}
                              title={`Firewall: ${r.action} port ${r.port}`}
                              className={`rounded px-1.5 py-0.5 font-mono text-[10px] ring-1 ${
                                r.action === "ALLOW"
                                  ? "bg-accent-2/10 text-accent-2 ring-accent-2/25"
                                  : "bg-danger/10 text-danger ring-danger/25"
                              }`}
                            >
                              {r.port} {r.action === "ALLOW" ? "OPEN" : "BLOCKED"}
                            </span>
                          ))
                        : d.ports.map((p) => (
                            <span
                              key={p}
                              className="rounded bg-surface-3 px-1.5 py-0.5 font-mono text-[10px] text-muted ring-1 ring-hairline"
                            >
                              {p}
                            </span>
                          ))}
                    </div>
                  </td>
                  <td className="px-3 py-2.5">
                    <span className={`flex items-center gap-1.5 text-xs ${meta.text}`}>
                      <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
                      {meta.label}
                    </span>
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    <button
                      onClick={() => onOverride(d.id)}
                      title="Toggle Human Override / retract policy"
                      className={`inline-flex items-center gap-1 rounded-lg px-2.5 py-1 text-[11px] font-medium ring-1 transition ${
                        d.status === "override"
                          ? "bg-warn/15 text-warn ring-warn/30 hover:bg-warn/25"
                          : "bg-surface-2 text-muted ring-hairline hover:bg-surface-3 hover:text-foreground"
                      }`}
                    >
                      <Power className="h-3 w-3" />
                      {d.status === "override" ? "Release" : "Override"}
                    </button>
                  </td>
                </motion.tr>
              );
            })}
          </tbody>
        </table>
        )}
      </div>
    </GlassCard>
  );
}
