"use client";

import { motion } from "framer-motion";
import type { ReactNode } from "react";

interface GlassCardProps {
  children: ReactNode;
  className?: string;
  /** Enable hover brightness-step lift. */
  interactive?: boolean;
  /** Stagger index for entrance animation. */
  delay?: number;
}

/** Base panel surface — flat, brightness-step elevation (no glass blur). */
export function GlassCard({
  children,
  className = "",
  interactive = false,
  delay = 0,
}: GlassCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay, ease: [0.22, 1, 0.36, 1] }}
      className={`glass ${interactive ? "glass-hover" : ""} rounded-[14px] ${className}`}
    >
      {children}
    </motion.div>
  );
}

interface PanelHeaderProps {
  title: string;
  icon?: ReactNode;
  subtitle?: string;
  action?: ReactNode;
}

/** Consistent header row for panels — uppercase mono label + optional subtitle. */
export function PanelHeader({ title, icon, subtitle, action }: PanelHeaderProps) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-hairline px-5 py-3.5">
      <div className="flex items-center gap-3">
        {icon && (
          <div className="grid h-8 w-8 place-items-center rounded-lg bg-surface-2 text-muted ring-1 ring-hairline">
            {icon}
          </div>
        )}
        <div>
          <h2 className="text-[13px] font-medium tracking-tight text-foreground">
            {title}
          </h2>
          {subtitle && <p className="section-label mt-0.5">{subtitle}</p>}
        </div>
      </div>
      {action}
    </div>
  );
}
