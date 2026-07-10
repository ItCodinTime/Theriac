"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { BarChart3 } from "lucide-react";
import { GlassCard, PanelHeader } from "./GlassCard";
import type { ThreatPoint } from "@/lib/types";

interface ThreatChartProps {
  data: ThreatPoint[];
}

export function ThreatChart({ data }: ThreatChartProps) {
  return (
    <GlassCard delay={0.15} className="flex h-full flex-col overflow-hidden">
      <PanelHeader
        title="Network Activity"
        subtitle="allow vs deny rules · per decision"
        icon={<BarChart3 className="h-4.5 w-4.5" />}
        action={<Legend />}
      />
      <div className="min-h-52 flex-1 px-2 pb-3">
        {data.length === 0 ? (
          <div className="flex h-full min-h-52 flex-col items-center justify-center text-center">
            <BarChart3 className="h-6 w-6 text-faint" />
            <p className="mt-3 text-sm text-muted">No enforcement activity yet</p>
            <p className="section-label mt-1">Runs & ingests plot allow/deny rules here</p>
          </div>
        ) : (
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 8, right: 10, left: -18, bottom: 0 }}>
            <defs>
              <linearGradient id="gAllowed" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#5b6cff" stopOpacity={0.45} />
                <stop offset="100%" stopColor="#5b6cff" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gBlocked" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#fb7185" stopOpacity={0.45} />
                <stop offset="100%" stopColor="#fb7185" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
            <XAxis
              dataKey="time"
              tick={{ fill: "rgba(255,255,255,0.35)", fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              minTickGap={28}
            />
            <YAxis
              tick={{ fill: "rgba(255,255,255,0.35)", fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              width={38}
            />
            <Tooltip
              contentStyle={{
                background: "#181818",
                border: "1px solid rgba(255,255,255,0.14)",
                borderRadius: 10,
                fontSize: 12,
              }}
              labelStyle={{ color: "rgba(255,255,255,0.6)" }}
              itemStyle={{ padding: 0 }}
            />
            <Area
              type="monotone"
              dataKey="allowed"
              stroke="#5b6cff"
              strokeWidth={2}
              fill="url(#gAllowed)"
              name="Allowed"
              isAnimationActive={false}
            />
            <Area
              type="monotone"
              dataKey="blocked"
              stroke="#fb7185"
              strokeWidth={2}
              fill="url(#gBlocked)"
              name="Blocked"
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
        )}
      </div>
    </GlassCard>
  );
}

function Legend() {
  return (
    <div className="flex items-center gap-3 text-[11px] text-muted">
      <span className="flex items-center gap-1.5">
        <span className="h-2 w-2 rounded-full bg-accent" /> Allowed
      </span>
      <span className="flex items-center gap-1.5">
        <span className="h-2 w-2 rounded-full bg-danger" /> Blocked
      </span>
    </div>
  );
}
