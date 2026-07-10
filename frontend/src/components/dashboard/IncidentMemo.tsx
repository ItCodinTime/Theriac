"use client";

import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { FileText, ShieldAlert, CheckCircle2, XCircle, Sparkles, Loader2 } from "lucide-react";
import { GlassCard, PanelHeader } from "./GlassCard";
import type { IncidentMemo as IncidentMemoType } from "@/lib/types";

/**
 * The backend memo step is sometimes clean and sometimes leaks the model's raw
 * reasoning (and a trailing "[ERROR: ...]"). Extract the well-formed
 * THREAT/ACTION/STATUS memo when present and drop the noise so cards stay tidy.
 */
function cleanMemoText(raw: string): string {
  let t = (raw || "").replace(/\[ERROR[^\]]*\]/gi, "").trim();
  const threatIdx = t.lastIndexOf("THREAT:");
  if (threatIdx >= 0) {
    t = t.slice(threatIdx).trim();
    const statusIdx = t.indexOf("STATUS:");
    if (statusIdx >= 0) {
      const period = t.indexOf(".", statusIdx);
      if (period >= 0) t = t.slice(0, period + 1).trim();
    }
  }
  return t || "No memo text returned.";
}

/** Only show a real CVE badge for genuine identifiers, not "NONE"/"N/A". */
function hasRealCve(cve: string | null): cve is string {
  return !!cve && /^CVE-/i.test(cve.trim());
}

interface IncidentMemoProps {
  memos: IncidentMemoType[];
  onExplain?: (memo: IncidentMemoType) => Promise<string>;
}

export function IncidentMemo({ memos, onExplain }: IncidentMemoProps) {
  return (
    <GlassCard delay={0.15} className="flex h-full flex-col overflow-hidden">
      <PanelHeader
        title="Incident Memos"
        subtitle="Contract B · agent decisions"
        icon={<FileText className="h-4.5 w-4.5" />}
      />
      <div className="slim-scroll flex-1 space-y-3 overflow-y-auto px-4 py-4">
        {memos.length === 0 ? (
          <div className="flex h-full min-h-40 flex-col items-center justify-center text-center">
            <FileText className="h-6 w-6 text-faint" />
            <p className="mt-3 text-sm text-muted">No decisions yet</p>
            <p className="section-label mt-1">Ingest a manual to generate a memo</p>
          </div>
        ) : (
          <AnimatePresence initial={false}>
            {memos.map((memo) => (
              <MemoCard key={memo.id} memo={memo} onExplain={onExplain} />
            ))}
          </AnimatePresence>
        )}
      </div>
    </GlassCard>
  );
}

function MemoCard({
  memo,
  onExplain,
}: {
  memo: IncidentMemoType;
  onExplain?: (memo: IncidentMemoType) => Promise<string>;
}) {
  const [expanded, setExpanded] = useState(false);
  const [explaining, setExplaining] = useState(false);
  const [explanation, setExplanation] = useState<string | null>(null);
  const [explainError, setExplainError] = useState<string | null>(null);
  const text = cleanMemoText(memo.memo_text);
  const isLong = text.length > 240;

  const handleExplain = async () => {
    if (!onExplain || explaining) return;
    if (explanation) {
      setExplanation(null);
      return;
    }
    setExplaining(true);
    setExplainError(null);
    try {
      setExplanation(await onExplain(memo));
    } catch (err) {
      setExplainError(err instanceof Error ? err.message : "Explanation failed");
    } finally {
      setExplaining(false);
    }
  };
  return (
    <motion.article
      layout
      initial={{ opacity: 0, y: -10, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, scale: 0.98 }}
      transition={{ duration: 0.3 }}
      className="rounded-xl bg-surface-2 p-3.5 ring-1 ring-hairline"
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-foreground">
              {memo.device_model}
            </span>
            <span className="rounded bg-surface-3 px-1.5 py-0.5 font-mono text-[10px] text-muted ring-1 ring-hairline">
              {memo.target_vpc_id}
            </span>
          </div>
          <span className="font-mono text-[11px] text-faint">
            {new Date(memo.created_at).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
            })}
          </span>
        </div>
        <ConfidenceGauge score={memo.confidence_score} />
      </div>

      <div className="mt-3 flex flex-wrap gap-1.5">
        {memo.firewall_rules.map((rule, i) => (
          <span
            key={`${rule.port}-${i}`}
            className={`flex items-center gap-1 rounded-md px-2 py-1 font-mono text-[11px] ring-1 ${
              rule.action === "ALLOW"
                ? "bg-accent-2/10 text-accent-2 ring-accent-2/25"
                : "bg-danger/10 text-danger ring-danger/25"
            }`}
          >
            {rule.action === "ALLOW" ? (
              <CheckCircle2 className="h-3 w-3" />
            ) : (
              <XCircle className="h-3 w-3" />
            )}
            {rule.action} · {rule.port}
          </span>
        ))}
      </div>

      <p
        className={`mt-3 text-[12px] leading-relaxed text-muted ${
          expanded ? "" : "line-clamp-3"
        }`}
      >
        {text}
      </p>
      {isLong && (
        <button
          onClick={() => setExpanded((v) => !v)}
          className="mt-1 text-[11px] font-medium text-accent transition hover:text-foreground"
        >
          {expanded ? "Show less" : "Show more"}
        </button>
      )}

      {hasRealCve(memo.cve_flagged) && (
        <div className="mt-2.5 flex items-center gap-1.5 rounded-md bg-danger/10 px-2 py-1 text-[11px] font-medium text-danger ring-1 ring-danger/20">
          <ShieldAlert className="h-3.5 w-3.5" />
          {memo.cve_flagged}
        </div>
      )}

      {onExplain && (
        <div className="mt-3 border-t border-hairline pt-2.5">
          <button
            onClick={handleExplain}
            disabled={explaining}
            className="flex items-center gap-1.5 text-[11px] font-medium text-accent transition hover:text-foreground disabled:opacity-60"
          >
            {explaining ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Sparkles className="h-3.5 w-3.5" />
            )}
            {explaining
              ? "Asking the agent…"
              : explanation
                ? "Hide explanation"
                : "Explain this decision"}
          </button>

          <AnimatePresence initial={false}>
            {explanation && (
              <motion.p
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.2 }}
                className="mt-2 overflow-hidden rounded-lg bg-primary/10 p-2.5 text-[12px] leading-relaxed text-muted ring-1 ring-accent/20"
              >
                {explanation}
              </motion.p>
            )}
          </AnimatePresence>
          {explainError && (
            <p className="mt-2 text-[11px] text-danger">Couldn&apos;t explain: {explainError}</p>
          )}
        </div>
      )}
    </motion.article>
  );
}

function ConfidenceGauge({ score }: { score: number }) {
  const tone = score >= 95 ? "#3ecf8e" : score >= 90 ? "#5b6cff" : "#f5b544";
  const r = 16;
  const c = 2 * Math.PI * r;
  const dash = (score / 100) * c;
  return (
    <div className="relative grid h-12 w-12 shrink-0 place-items-center">
      <svg viewBox="0 0 40 40" className="h-12 w-12 -rotate-90">
        <circle cx="20" cy="20" r={r} fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="4" />
        <circle
          cx="20"
          cy="20"
          r={r}
          fill="none"
          stroke={tone}
          strokeWidth="4"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${c}`}
        />
      </svg>
      <span className="absolute font-mono text-[11px] font-semibold text-foreground">
        {score}
      </span>
    </div>
  );
}
