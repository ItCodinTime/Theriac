"use client";

import { useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ScrollText, RefreshCw, ShieldAlert, Trash2, Undo2 } from "lucide-react";
import { GlassCard, PanelHeader } from "./GlassCard";
import type { AuditEntry } from "@/lib/types";

interface AuditTableProps {
  entries: AuditEntry[];
  loading: boolean;
  onRefresh: () => void;
}

const DISMISSED_STORAGE_KEY = "panacea:audit:dismissed";

function fmtTime(iso?: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString([], {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function hasRealCve(cve?: string): cve is string {
  return !!cve && /^CVE-/i.test(cve.trim());
}

/**
 * Content signature for an entry (ignores timestamp + lease id) so identical
 * repeated decisions collapse into a single row and share a stable key for
 * local dismissal.
 */
function entryKey(e: AuditEntry): string {
  const rules = (e.firewall_rules ?? [])
    .map((r) => `${r.port}:${r.action}`)
    .join(",");
  return [
    e.device_model ?? "",
    e.firmware_version ?? "",
    e.confidence_score ?? "",
    e.cve_flagged ?? "",
    rules,
    e.drift_alert ?? "",
  ].join("|");
}

/** Real append-only decision history from GET /api/v1/agent/audit. */
export function AuditTable({ entries, loading, onRefresh }: AuditTableProps) {
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());

  useEffect(() => {
    try {
      const raw = localStorage.getItem(DISMISSED_STORAGE_KEY);
      // Read persisted dismissals after mount to avoid hydration mismatch.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      if (raw) setDismissed(new Set(JSON.parse(raw) as string[]));
    } catch {
      // ignore malformed / unavailable storage
    }
  }, []);

  const persist = (next: Set<string>) => {
    setDismissed(next);
    try {
      localStorage.setItem(DISMISSED_STORAGE_KEY, JSON.stringify([...next]));
    } catch {
      // ignore storage failures (private mode etc.)
    }
  };

  // Collapse identical decisions into one row with an occurrence count.
  const grouped = useMemo(() => {
    const map = new Map<string, { entry: AuditEntry; count: number }>();
    for (const e of entries) {
      const k = entryKey(e);
      const existing = map.get(k);
      if (existing) existing.count += 1;
      else map.set(k, { entry: e, count: 1 });
    }
    return [...map.entries()].map(([key, v]) => ({ key, ...v }));
  }, [entries]);

  const visible = grouped.filter((g) => !dismissed.has(g.key));
  const hiddenCount = grouped.length - visible.length;

  const deleteOne = (key: string) => {
    const next = new Set(dismissed);
    next.add(key);
    persist(next);
  };

  const clearAll = () => {
    const next = new Set(dismissed);
    grouped.forEach((g) => next.add(g.key));
    persist(next);
  };

  const restoreHidden = () => persist(new Set());

  return (
    <GlassCard delay={0.1} className="flex h-full flex-col overflow-hidden">
      <PanelHeader
        title="Decision Audit Trail"
        subtitle="rest · /agent/audit"
        icon={<ScrollText className="h-4 w-4" />}
        action={
          <div className="flex items-center gap-2">
            {hiddenCount > 0 && (
              <button
                onClick={restoreHidden}
                className="flex items-center gap-1.5 rounded-lg bg-surface-2 px-3 py-1.5 text-xs font-medium text-muted ring-1 ring-hairline transition hover:text-foreground"
              >
                <Undo2 className="h-3.5 w-3.5" />
                Restore {hiddenCount} hidden
              </button>
            )}
            {visible.length > 0 && (
              <button
                onClick={clearAll}
                className="flex items-center gap-1.5 rounded-lg bg-surface-2 px-3 py-1.5 text-xs font-medium text-muted ring-1 ring-hairline transition hover:text-danger"
              >
                <Trash2 className="h-3.5 w-3.5" />
                Clear all
              </button>
            )}
            <button
              onClick={onRefresh}
              disabled={loading}
              className="flex items-center gap-1.5 rounded-lg bg-surface-2 px-3 py-1.5 text-xs font-medium text-muted ring-1 ring-hairline transition hover:text-foreground disabled:opacity-60"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>
        }
      />
      <div className="slim-scroll flex-1 overflow-auto px-2 pb-2">
        {visible.length === 0 ? (
          <div className="flex h-full min-h-48 flex-col items-center justify-center text-center">
            <ScrollText className="h-6 w-6 text-faint" />
            <p className="mt-3 text-sm text-muted">
              {loading
                ? "Loading audit log…"
                : hiddenCount > 0
                  ? "All entries hidden"
                  : "No recorded decisions yet"}
            </p>
            <p className="section-label mt-1">Every real agent decision is logged here</p>
          </div>
        ) : (
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="text-left">
                <th className="section-label px-3 py-2.5">Time</th>
                <th className="section-label px-3 py-2.5">Device</th>
                <th className="section-label px-3 py-2.5">Confidence</th>
                <th className="section-label px-3 py-2.5">CVE</th>
                <th className="section-label px-3 py-2.5">Rules</th>
                <th className="section-label px-3 py-2.5">Drift</th>
                <th className="section-label px-3 py-2.5"></th>
              </tr>
            </thead>
            <tbody>
              <AnimatePresence initial={false}>
                {visible.map(({ key, entry: e, count }) => (
                  <motion.tr
                    key={key}
                    layout
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0, height: 0 }}
                    className="group border-t border-hairline align-top transition hover:bg-surface-2"
                  >
                    <td className="px-3 py-2.5 font-mono text-[11px] text-muted">
                      {fmtTime(e.timestamp)}
                      {count > 1 && (
                        <span className="ml-1.5 rounded bg-surface-3 px-1 py-0.5 text-[9px] font-semibold text-muted ring-1 ring-hairline">
                          ×{count}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="font-medium text-foreground">{e.device_model ?? "—"}</div>
                      <div className="font-mono text-[10px] text-faint">
                        {e.firmware_version ? `fw ${e.firmware_version}` : e.operator_id ?? ""}
                      </div>
                    </td>
                    <td className="px-3 py-2.5">
                      {typeof e.confidence_score === "number" ? (
                        <span
                          className={`font-mono text-sm ${
                            e.confidence_score >= 90
                              ? "text-accent-2"
                              : e.confidence_score >= 70
                                ? "text-accent"
                                : "text-warn"
                          }`}
                        >
                          {e.confidence_score}%
                        </span>
                      ) : (
                        <span className="text-faint">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      {hasRealCve(e.cve_flagged) ? (
                        <span className="inline-flex items-center gap-1 rounded bg-danger/10 px-1.5 py-0.5 font-mono text-[10px] text-danger ring-1 ring-danger/25">
                          <ShieldAlert className="h-3 w-3" />
                          {e.cve_flagged}
                        </span>
                      ) : (
                        <span className="text-faint">none</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {(e.firewall_rules ?? []).map((r, j) => (
                          <span
                            key={`${r.port}-${j}`}
                            className={`rounded px-1.5 py-0.5 font-mono text-[10px] ring-1 ${
                              r.action === "ALLOW"
                                ? "bg-accent-2/10 text-accent-2 ring-accent-2/25"
                                : "bg-danger/10 text-danger ring-danger/25"
                            }`}
                          >
                            {r.port} {r.action === "ALLOW" ? "OPEN" : "BLOCK"}
                          </span>
                        ))}
                        {!(e.firewall_rules ?? []).length && <span className="text-faint">—</span>}
                      </div>
                    </td>
                    <td className="px-3 py-2.5 text-[11px] text-muted">
                      {e.drift_alert ? (
                        <span className="text-warn">{e.drift_alert}</span>
                      ) : (
                        <span className="text-faint">stable</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5 text-right">
                      <button
                        onClick={() => deleteOne(key)}
                        title="Remove from view"
                        aria-label="Remove entry"
                        className="rounded-md p-1.5 text-faint opacity-0 ring-1 ring-transparent transition hover:bg-danger/10 hover:text-danger hover:ring-danger/25 group-hover:opacity-100"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </motion.tr>
                ))}
              </AnimatePresence>
            </tbody>
          </table>
        )}
      </div>
    </GlassCard>
  );
}
