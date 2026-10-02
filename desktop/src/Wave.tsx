import { useEffect, useRef } from "react";

// A line with a sharp, jagged pulse running along it from one end to the
// other, as part of the line itself: traffic, going somewhere. The pulse
// keeps its size and its pace the whole way; only the line's two ends are
// held straight, so the pulse rises out of the line at one end and irons
// flat into it at the other, spike by spike, front first. The same shape,
// small and still, says "connected" beside this device's name.

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

/// How far the line stands off straight at `x` along a line `width` long:
/// not at all at either end, fully once `reach` in from it, eased between.
/// Each point of the pulse is lifted by this where it is, so a spike
/// flattens as it gets to the end, not the whole pulse at once.
function lift(x: number, width: number, reach: number): number {
  const d = Math.min(x, width - x) / reach;
  return d <= 0 ? 0 : d >= 1 ? 1 : d * d * (3 - 2 * d);
}

const reduced = typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

function path(width: number, mid: number, amp: number, pulse: number, at: number): string {
  // How far in from each end the line is held straight: half the pulse's
  // length, so its front spikes are flat while the ones behind are still
  // whole. Any longer and the pulse seems to shrink; any shorter and it
  // seems to hit a wall.
  const reach = Math.min(pulse * 0.5, width * 0.3);
  let d = `M${Math.min(0, at).toFixed(2)} ${mid}`;
  for (const [x, y] of SHAPE) {
    const px = at + x * pulse;
    d += ` L${px.toFixed(2)} ${(mid + y * amp * lift(px, width, reach)).toFixed(2)}`;
  }
  return d + ` L${Math.max(width, at + pulse).toFixed(2)} ${mid}`;
}

/// The share of each period the pulse spends crossing; the rest is plain
/// line, so each pulse reads as one going out.
const TRAVEL = 0.85;

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
      const f = ((t - start) % period) / (period * TRAVEL);
      // From wholly past the left end to wholly past the right, at one pace;
      // both ends are straight, so it is never cut off by the edge.
      p.setAttribute("d", f >= 1 ? `M0 ${mid} L${w} ${mid}` : path(w, mid, amp, pulse, -pulse + f * (w + pulse)));
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
