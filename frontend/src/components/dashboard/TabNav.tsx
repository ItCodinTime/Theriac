"use client";

import { motion } from "framer-motion";
import type { LucideIcon } from "lucide-react";

export interface TabDef {
  id: string;
  label: string;
  icon: LucideIcon;
  hint?: string;
}

interface TabNavProps {
  tabs: TabDef[];
  active: string;
  onChange: (id: string) => void;
}

/** Compact segmented navigation between the main dashboard views. */
export function TabNav({ tabs, active, onChange }: TabNavProps) {
  return (
    <div className="glass flex w-full gap-1 rounded-[10px] p-1 sm:w-auto">
      {tabs.map((tab) => {
        const Icon = tab.icon;
        const isActive = tab.id === active;
        return (
          <button
            key={tab.id}
            onClick={() => onChange(tab.id)}
            className={`relative flex flex-1 items-center justify-center gap-2 rounded-lg px-4 py-2 text-[13px] font-medium transition-colors sm:flex-none ${
              isActive ? "text-white" : "text-muted hover:text-foreground"
            }`}
          >
            {isActive && (
              <motion.span
                layoutId="tab-active"
                transition={{ type: "spring", stiffness: 440, damping: 36 }}
                className="absolute inset-0 rounded-lg bg-primary"
              />
            )}
            <Icon className="relative h-4 w-4" />
            <span className="relative">{tab.label}</span>
          </button>
        );
      })}
    </div>
  );
}
