"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  TerminalSquare,
  Play,
  Loader2,
  ChevronRight,
  Check,
  Brain,
  ShieldAlert,
  TriangleAlert,
  CircleDot,
  Cpu,
} from "lucide-react";
import { GlassCard, PanelHeader } from "./GlassCard";
import type { AgentLogLine, LogLevel } from "@/lib/types";

interface AgentTerminalProps {
  logs: AgentLogLine[];
  running: boolean;
  onRun: () => void;
}

/* ------------------------------------------------------------------ */
/* Grouping: collapse the flat reasoning stream into Cursor-style rows */
/* ------------------------------------------------------------------ */

type ActivityKind = "thinking" | "milestone" | "event";

interface ActivityGroup {
  id: string;
  kind: ActivityKind;
  label: string;
  level: LogLevel;
  ts: number;
  lines: AgentLogLine[];
}

const MARKER_RE = /\[(?:STEP[^\]]*|FALLBACK|HUMAN OVERRIDE|DONE)\]/i;

function truncate(s: string, n: number) {
  const t = s.trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
}

/** Turn a raw content line into a short, human-readable row label. */
function labelFor(line: AgentLogLine): string {
  const raw = line.text.trim();
  const m = raw.match(/\[([^\]]+)\]/);
  if (m) {
    const tag = m[1].toUpperCase();
    const rest = raw.replace(/\[[^\]]+\]/, "").trim();
    let name = tag;
    if (/HUMAN OVERRIDE/.test(tag)) name = "Human override";
    else if (/FALLBACK/.test(tag)) name = "Fallback decision";
    else if (/STEP/.test(tag))
      name = tag
        .replace(/STEP\s*/i, "Step ")
        .replace(/\bDONE\b/i, "· done")
        .trim();
    return rest ? `${name} — ${truncate(rest, 56)}` : name;
  }
  return truncate(raw, 72);
}

/** Consecutive "reasoning" tokens fold into one Thinking block; every content
 *  line (milestone marker or event) becomes its own collapsible row. */
function groupLogs(logs: AgentLogLine[]): ActivityGroup[] {
  const groups: ActivityGroup[] = [];
  for (const line of logs) {
    const last = groups[groups.length - 1];
    if (line.dim) {
      if (last && last.kind === "thinking") {
        last.lines.push(line);
        last.ts = line.ts;
      } else {
        groups.push({ id: line.id, kind: "thinking", label: "Reasoning", level: "info", ts: line.ts, lines: [line] });
      }
      continue;
    }
    const isMarker = MARKER_RE.test(line.text) || line.level === "system";
    groups.push({
      id: line.id,
      kind: isMarker ? "milestone" : "event",
      label: labelFor(line),
      level: line.level,
      ts: line.ts,
      lines: [line],
    });
  }
  return groups;
}

const LEVEL_TEXT: Record<LogLevel, string> = {
  info: "text-muted",
  success: "text-accent-2",
  warn: "text-warn",
  threat: "text-danger",
  system: "text-accent",
};

function fmtTime(ts: number) {
  return new Date(ts).toLocaleTimeString([], {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function AgentTerminal({ logs, running, onRun }: AgentTerminalProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [view, setView] = useState<"steps" | "raw">("steps");
  const [open, setOpen] = useState<Set<string>>(new Set());

  const groups = useMemo(() => groupLogs(logs), [logs]);

  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [logs, view]);

  const toggle = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <GlassCard delay={0.1} className="flex h-full flex-col overflow-hidden">
      <PanelHeader
        title="Agent Reasoning Stream"
        subtitle="ws · /agent-stream"
        icon={<TerminalSquare className="h-4 w-4" />}
        action={
          <div className="flex items-center gap-2">
            <div className="flex rounded-lg bg-surface-2 p-0.5 ring-1 ring-hairline">
              {(["steps", "raw"] as const).map((v) => (
                <button
                  key={v}
                  onClick={() => setView(v)}
                  className={`rounded-md px-2.5 py-1 text-[11px] font-medium capitalize transition-colors ${
                    view === v ? "bg-surface-3 text-foreground" : "text-faint hover:text-muted"
                  }`}
                >
                  {v}
                </button>
              ))}
            </div>
            <button
              onClick={onRun}
              disabled={running}
              className="flex items-center gap-1.5 rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-white transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {running ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> Running
                </>
              ) : (
                <>
                  <Play className="h-3.5 w-3.5" /> Run Agent
                </>
              )}
            </button>
          </div>
        }
      />

      <div
        ref={scrollRef}
        className="slim-scroll recessed relative m-3 mt-3 flex-1 overflow-y-auto rounded-xl p-2 font-mono text-[12px] leading-relaxed"
      >
        {view === "raw" ? (
          <RawLog logs={logs} running={running} />
        ) : (
          <div className="flex flex-col">
            <AnimatePresence initial={false}>
              {groups.map((g, i) => {
                const isLast = i === groups.length - 1;
                const isActive = running && isLast;
                const isError = g.level === "warn" || g.level === "threat";
                const expandable =
                  g.kind === "thinking" || isError || g.lines[0].text.length > 76;
                const isOpen = open.has(g.id) || (isActive && g.kind === "thinking");
                return (
                  <ActivityRow
                    key={g.id}
                    group={g}
                    active={isActive}
                    expandable={expandable}
                    open={isOpen}
                    onToggle={() => toggle(g.id)}
                  />
                );
              })}
            </AnimatePresence>
            {running && groups.length === 0 && (
              <div className="flex items-center gap-2 px-2 py-1 text-faint">
                <Loader2 className="h-3.5 w-3.5 animate-spin text-accent" /> Waiting for agent…
              </div>
            )}
          </div>
        )}
      </div>
    </GlassCard>
  );
}

function StatusIcon({ group, active }: { group: ActivityGroup; active: boolean }) {
  if (active)
    return <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-accent" />;
  if (group.kind === "thinking")
    return <Brain className="h-3.5 w-3.5 shrink-0 text-accent-3" />;
  switch (group.level) {
    case "threat":
      return <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-danger" />;
    case "warn":
      return <TriangleAlert className="h-3.5 w-3.5 shrink-0 text-warn" />;
    case "success":
      return <Check className="h-3.5 w-3.5 shrink-0 text-accent-2" />;
    case "system":
      return <Cpu className="h-3.5 w-3.5 shrink-0 text-accent" />;
    default:
      return <CircleDot className="h-3 w-3 shrink-0 text-faint" />;
  }
}

function ActivityRow({
  group,
  active,
  expandable,
  open,
  onToggle,
}: {
  group: ActivityGroup;
  active: boolean;
  expandable: boolean;
  open: boolean;
  onToggle: () => void;
}) {
  const count = group.kind === "thinking" ? group.lines.length : 0;
  const errorTint =
    group.level === "threat" ? "bg-danger/5" : group.level === "warn" ? "bg-warn/5" : "";
  return (
    <motion.div
      initial={{ opacity: 0, x: -6 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.2 }}
      className="rounded-md"
    >
      <button
        onClick={expandable ? onToggle : undefined}
        className={`flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left transition-colors ${errorTint} ${
          expandable ? "hover:bg-surface-2" : "cursor-default"
        }`}
      >
        {expandable ? (
          <ChevronRight
            className={`h-3 w-3 shrink-0 text-faint transition-transform ${open ? "rotate-90" : ""}`}
          />
        ) : (
          <span className="w-3 shrink-0" />
        )}
        <StatusIcon group={group} active={active} />
        <span
          className={`flex-1 truncate ${
            group.kind === "thinking" ? "italic text-faint" : LEVEL_TEXT[group.level]
          }`}
        >
          {group.label}
          {count > 1 && <span className="ml-1.5 text-faint">· {count}</span>}
        </span>
        <span className="shrink-0 text-[10px] text-faint">{fmtTime(group.ts)}</span>
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="ml-6 border-l border-hairline py-1 pl-3">
              {group.lines.map((l) => (
                <p
                  key={l.id}
                  className={`whitespace-pre-wrap py-0.5 ${
                    l.dim ? "italic text-faint" : "text-muted"
                  }`}
                >
                  {l.text}
                </p>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

/** Flat, unstyled firehose — the "Raw" toggle. */
function RawLog({ logs, running }: { logs: AgentLogLine[]; running: boolean }) {
  return (
    <div className="px-1">
      {logs.map((line) => (
        <div key={line.id} className="flex gap-2 py-0.5">
          <span className="shrink-0 text-[10px] text-faint">{fmtTime(line.ts)}</span>
          {line.step != null && (
            <span className={`shrink-0 font-semibold ${LEVEL_TEXT[line.level]}`}>
              [{line.step}]
            </span>
          )}
          <span
            className={
              line.dim ? "whitespace-pre-wrap italic text-faint" : `whitespace-pre-wrap ${LEVEL_TEXT[line.level]}`
            }
          >
            {line.text}
          </span>
        </div>
      ))}
      {running && (
        <div className="py-0.5">
          <span className="inline-block h-3 w-1.5 animate-pulse bg-accent" />
        </div>
      )}
    </div>
  );
}
