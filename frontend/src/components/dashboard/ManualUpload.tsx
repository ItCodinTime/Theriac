"use client";

import { useRef, useState } from "react";
import { UploadCloud, FileText, Loader2, Cpu, ShieldCheck, Brain } from "lucide-react";
import { GlassCard, PanelHeader } from "./GlassCard";

interface ManualUploadProps {
  uploading: boolean;
  onUpload: (file: File) => void;
}

const STEPS = [
  { icon: FileText, label: "Extract", text: "Agent parses the manual's ports & protocols" },
  { icon: Brain, label: "Reason", text: "Weighs each rule against zero-trust policy" },
  { icon: ShieldCheck, label: "Enforce", text: "Emits a Contract B firewall lockdown" },
  { icon: Cpu, label: "Register", text: "Adds the machine to the monitored fleet" },
];

/** Drag-and-drop zone for ingesting a medical-device manual PDF. */
export function ManualUpload({ uploading, onUpload }: ManualUploadProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [lastFile, setLastFile] = useState<string | null>(null);

  const accept = (file?: File | null) => {
    if (!file) return;
    if (!/\.pdf$/i.test(file.name) && file.type !== "application/pdf") return;
    setLastFile(file.name);
    onUpload(file);
  };

  return (
    <GlassCard delay={0.1} className="overflow-hidden">
      <PanelHeader
        title="Ingest Device Manual"
        subtitle="pdf · in-browser extract → agent"
        icon={<UploadCloud className="h-4 w-4" />}
      />
      <div className="p-5">
        <div
          role="button"
          tabIndex={0}
          onClick={() => !uploading && inputRef.current?.click()}
          onKeyDown={(e) => {
            if ((e.key === "Enter" || e.key === " ") && !uploading) inputRef.current?.click();
          }}
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            if (!uploading) accept(e.dataTransfer.files?.[0]);
          }}
          className={`flex min-h-52 cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed p-8 text-center transition-colors ${
            dragging
              ? "border-accent bg-primary/10"
              : "border-white/15 bg-recessed hover:border-accent/60"
          } ${uploading ? "pointer-events-none opacity-70" : ""}`}
        >
          <input
            ref={inputRef}
            type="file"
            accept="application/pdf,.pdf"
            className="hidden"
            onChange={(e) => accept(e.target.files?.[0])}
          />
          {uploading ? (
            <>
              <Loader2 className="h-8 w-8 animate-spin text-accent" />
              <p className="mt-3 text-sm font-medium text-foreground">
                Agent is reading {lastFile ?? "the manual"}…
              </p>
              <p className="section-label mt-1">Watch the reasoning in Live Agent</p>
            </>
          ) : (
            <>
              <div className="grid h-12 w-12 place-items-center rounded-xl bg-surface-2 ring-1 ring-hairline">
                <UploadCloud className="h-6 w-6 text-accent" />
              </div>
              <p className="mt-3 text-sm font-medium text-foreground">
                Drop a device manual PDF here
              </p>
              <p className="mt-1 text-xs text-muted">
                or <span className="text-accent">browse</span> to upload · the agent
                analyzes it and enforces a firewall policy
              </p>
            </>
          )}
        </div>

        <div className="mt-4 grid gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
          {STEPS.map((s, i) => {
            const Icon = s.icon;
            return (
              <div
                key={s.label}
                className="rounded-lg bg-surface-2 p-3 ring-1 ring-hairline"
              >
                <div className="flex items-center gap-2">
                  <Icon className="h-4 w-4 text-accent" />
                  <span className="text-xs font-medium text-foreground">
                    {i + 1}. {s.label}
                  </span>
                </div>
                <p className="mt-1.5 text-[11px] leading-relaxed text-muted">{s.text}</p>
              </div>
            );
          })}
        </div>
      </div>
    </GlassCard>
  );
}
