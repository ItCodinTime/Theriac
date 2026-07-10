"use client";

import { useEffect, useRef, useState } from "react";
import { ecgSample } from "@/lib/simulator";
import type { VitalSample } from "@/lib/types";

interface UseHeartbeatOptions {
  /** Beats per minute driving the waveform cadence. */
  bpm?: number;
  /** Number of samples kept in the rolling window. */
  window?: number;
  /** Sampling interval in ms. */
  intervalMs?: number;
}

/**
 * Produces a rolling ECG-style waveform.
 *
 * This is the swap point for real device vitals: replace the interval that
 * calls `ecgSample` with values pushed from the backend telemetry stream.
 */
export function useHeartbeat({
  bpm = 72,
  window = 160,
  intervalMs = 40,
}: UseHeartbeatOptions = {}): VitalSample[] {
  const [samples, setSamples] = useState<VitalSample[]>(() =>
    Array.from({ length: window }, (_, i) => ({ t: i, value: 0 })),
  );
  const phaseRef = useRef(0);
  const tRef = useRef(window);

  useEffect(() => {
    // A full PQRST cycle should span one beat: (60 / bpm) seconds.
    const cyclesPerTick = intervalMs / 1000 / (60 / bpm);

    const id = setInterval(() => {
      phaseRef.current += cyclesPerTick;
      const value = ecgSample(phaseRef.current);
      const t = tRef.current++;
      setSamples((prev) => {
        const next = prev.slice(1);
        next.push({ t, value });
        return next;
      });
    }, intervalMs);

    return () => clearInterval(id);
  }, [bpm, intervalMs]);

  return samples;
}
