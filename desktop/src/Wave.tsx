import { useEffect, useRef } from "react";

// A line with a sharp, jagged pulse running along it from one end to the
// other, as part of the line itself: traffic, going somewhere. The same
// shape, small and still, says "connected" beside this device's name.

/// The pulse, left to right, as [x, y] with y from -1 (up) to 1 (down): a
/// small lift, then the big swings, then settling back to the line.
const SHAPE: [number, number][] = [
  [0, 0],
  [0.1, -0.28],
  [0.2, 0.36],
  [0.32, -1],
  [0.46, 0.92],
  [0.6, -0.62],
  [0.72, 0.3],
  [0.82, -0.12],
  [0.9, 0],
  [1, 0],
];

const reduced = typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

function path(width: number, mid: number, amp: number, pulse: number, at: number): string {
  // The flat line runs past both ends so the pulse can enter and leave
  // whole; the svg clips it.
  let d = `M${-pulse} ${mid} L${at} ${mid}`;
  for (const [x, y] of SHAPE) d += ` L${(at + x * pulse).toFixed(2)} ${(mid + y * amp).toFixed(2)}`;
  return d + ` L${width + pulse} ${mid}`;
}

/// Travelling: fills its container's width, one pulse crossing every
/// `period` ms. Still (`live` off, or reduced motion): the pulse parked in
/// the middle, or — `flat` — no pulse at all.
export function Wave({
  height = 24,
  pulse = 46,
  period = 2400,
  live = true,
  flat = false,
  className = "",
  strokeWidth = 1.5,
}: {
  height?: number;
  pulse?: number;
  period?: number;
  live?: boolean;
  flat?: boolean;
  className?: string;
  strokeWidth?: number;
}) {
  const svg = useRef<SVGSVGElement>(null);
  const line = useRef<SVGPathElement>(null);

  useEffect(() => {
    const el = svg.current;
    const p = line.current;
    if (!el || !p) return;
    const mid = height / 2;
    const amp = height / 2 - strokeWidth;
    const width = () => el.clientWidth || 100;

    if (flat) {
      p.setAttribute("d", `M0 ${mid} L${width()} ${mid}`);
      return;
    }
    if (!live || reduced) {
      const w = width();
      p.setAttribute("d", path(w, mid, amp, pulse, (w - pulse) / 2));
      return;
    }

    let raf = 0;
    const start = performance.now();
    const tick = (t: number) => {
      const w = width();
      const f = ((t - start) % period) / period;
      // Ease in and out a little, so the pulse seems to gather speed across
      // the line rather than slide at a constant rate.
      const e = f < 0.5 ? 2 * f * f : 1 - Math.pow(-2 * f + 2, 2) / 2;
      p.setAttribute("d", path(w, mid, amp, pulse, -pulse + e * (w + pulse)));
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [height, pulse, period, live, flat, strokeWidth]);

  return (
    <svg ref={svg} height={height} className={`block w-full overflow-hidden ${className}`} aria-hidden="true">
      <path ref={line} fill="none" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/// The small, still pulse that stands for "connected": a heartbeat, where
/// the rest of the window shows no colour to carry it. Flat when off.
export function Pulse({ on, className = "" }: { on: boolean; className?: string }) {
  const d = on
    ? "M0 6 L4 6 L5.2 4.3 L6.6 8.2 L8.4 1.2 L10.4 10.8 L12 3.6 L13.2 7.4 L14.2 6 L20 6"
    : "M0 6 L20 6";
  return (
    <svg width="20" height="12" viewBox="0 0 20 12" className={`shrink-0 ${className}`} aria-hidden="true">
      <path d={d} fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" className="transition-all duration-300" />
    </svg>
  );
}
