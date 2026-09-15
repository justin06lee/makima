import { useEffect, useId, useMemo, useRef, type CSSProperties } from "react";
import { f, rng } from "./pen";

/// Makima's eye: a golden iris ringed like a ripple, the way hers is drawn,
/// tucked under a heavy upper lid with a dark wing at the outer corner. The
/// same drawing as the website's.
///
/// In the app it is also the status light. Open means this device is on the
/// network; shut means it is not. Open, it follows the pointer around the
/// window and blinks now and then. Following writes one transform straight
/// onto the iris rather than going through React state, because a pointer
/// move would otherwise re-render a picture whose markup never changes.

const CX = 330;
const CY = 158;
/** Iris radius: both lids cut into it, which is what makes the stare hers. */
const R = 108;
/** How far the iris travels at full stretch. */
const MX = 92;
const MY = 26;

const ALMOND =
  "M36 176C114 112 240 72 352 74C466 76 556 106 610 138C560 194 452 238 332 240C212 242 106 222 36 176Z";
const LASH_TOP = "M30 176C108 98 238 56 354 56C472 56 566 94 642 116";
const LASH = `${LASH_TOP}C628 122 617 129 610 138C556 106 466 76 352 74C240 72 114 112 36 176Z`;
const LOWER = "M60 190C136 228 226 240 332 240C446 240 548 200 604 146";
/** Shut: the line where the lids meet, and the lashes hanging from it. */
const SHUT = "M44 150C150 212 470 218 612 138";
const SHUT_LASHES = "M158 186L146 212M249 196L242 226M314 197L314 229M414 192L420 223M509 176L524 203M564 160L586 181";

const DARK_RINGS: [number, number][] = [
  [98, 4.5],
  [82, 4],
  [66, 3.4],
  [50, 3],
];
const LIGHT_RINGS = [90, 74, 58];

function fibres(seed: number, n: number) {
  const rand = rng(seed);
  let light = "";
  let dark = "";
  for (let i = 0; i < n; i++) {
    const a = (i / n) * Math.PI * 2 + (rand() - 0.5) * 0.06;
    const r1 = 32 + rand() * 10;
    const r2 = 88 + rand() * 16;
    const seg =
      `M${f(CX + r1 * Math.cos(a))} ${f(CY + r1 * Math.sin(a))}` +
      `L${f(CX + r2 * Math.cos(a))} ${f(CY + r2 * Math.sin(a))}`;
    if (rand() < 0.55) light += seg;
    else dark += seg;
  }
  return { light, dark };
}

/** The iris, moved and foreshortened as it turns toward an edge. */
function irisAt(x: number, y: number): string {
  const sx = 1 - 0.12 * Math.abs(x);
  const sy = 1 - 0.08 * Math.abs(y);
  return `matrix(${f(sx * 1000) / 1000} 0 0 ${f(sy * 1000) / 1000} ${f(x * MX + CX * (1 - sx))} ${f(y * MY + CY * (1 - sy))})`;
}

export function Eye({
  className = "",
  style,
  open = true,
  follow = false,
  blink = false,
  glow = false,
  look = [0, 0],
  detail = 96,
  seed = 1,
}: {
  className?: string;
  style?: CSSProperties;
  /** Shut is a thin dark line: the lids closed. */
  open?: boolean;
  /** Watch the pointer while it is over the window. */
  follow?: boolean;
  /** Blink now and then while open. */
  blink?: boolean;
  /** A haze of gold and red behind it. */
  glow?: boolean;
  /** Where a still eye looks, from -1 to 1 on each axis. */
  look?: [number, number];
  /** How many fibres the iris is drawn with. Fewer for small eyes. */
  detail?: number;
  seed?: number;
}) {
  const id = `eye${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const svg = useRef<SVGSVGElement>(null);
  const body = useRef<SVGGElement>(null);
  const iris = useRef<SVGGElement>(null);
  const fib = useMemo(() => fibres(seed, detail), [seed, detail]);

  useEffect(() => {
    const el = svg.current;
    if (!el || !open || (!follow && !blink)) return;
    // Someone who asked for less motion gets a still picture.
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    let x = 0;
    let y = 0;
    let tx = 0;
    let ty = 0;
    let raf = 0;
    let blinkTimer = 0;

    const tick = () => {
      x += (tx - x) * 0.14;
      y += (ty - y) * 0.14;
      iris.current?.setAttribute("transform", irisAt(x, y));
      raf = Math.abs(tx - x) + Math.abs(ty - y) > 0.002 ? requestAnimationFrame(tick) : 0;
    };
    const aim = (nx: number, ny: number) => {
      tx = nx;
      ty = ny;
      if (!raf) raf = requestAnimationFrame(tick);
    };

    const onMove = (e: PointerEvent) => {
      const r = el.getBoundingClientRect();
      const dx = e.clientX - (r.left + r.width / 2);
      const dy = e.clientY - (r.top + r.height / 2);
      const d = Math.hypot(dx, dy) || 1;
      // A small eye reaches full stretch sooner than a big one, so it still
      // visibly looks across a whole window.
      const k = Math.min(1, d / Math.max(120, r.width * 0.6));
      aim((dx / d) * k, (dy / d) * k);
    };
    const onOut = (e: PointerEvent) => {
      if (!e.relatedTarget) aim(0, 0);
    };

    const shut = () => {
      if (!document.hidden && body.current) {
        const twice = Math.random() < 0.18;
        const o = { transform: "scaleY(1)" };
        const c = { transform: "scaleY(0.05)" };
        body.current.animate(
          twice ? [o, { ...c, offset: 0.22 }, { ...o, offset: 0.45 }, { ...c, offset: 0.67 }, o] : [o, { ...c, offset: 0.45 }, o],
          { duration: twice ? 440 : 220, easing: "ease-in-out" },
        );
      }
      blinkTimer = window.setTimeout(shut, 3200 + Math.random() * 5600);
    };

    if (follow) {
      window.addEventListener("pointermove", onMove, { passive: true });
      window.addEventListener("pointerout", onOut);
    }
    if (blink) blinkTimer = window.setTimeout(shut, 1800 + Math.random() * 2400);

    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerout", onOut);
      window.clearTimeout(blinkTimer);
      cancelAnimationFrame(raf);
      iris.current?.setAttribute("transform", irisAt(look[0], look[1]));
    };
  }, [follow, blink, open, look]);

  return (
    <svg ref={svg} viewBox="16 36 636 220" className={`overflow-visible ${className}`} style={style} aria-hidden="true">
      <defs>
        <clipPath id={`${id}-almond`}>
          <path d={ALMOND} />
        </clipPath>
        <radialGradient id={`${id}-sclera`} cx="50%" cy="62%" r="60%">
          <stop offset="0" stopColor="#f7f1e8" />
          <stop offset="0.5" stopColor="#e2d6c7" />
          <stop offset="0.85" stopColor="#a39080" />
          <stop offset="1" stopColor="#6a574c" />
        </radialGradient>
        <radialGradient id={`${id}-iris`} cx={CX} cy={CY} r={R} gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#fff2c2" />
          <stop offset="0.24" stopColor="#ffd46b" />
          <stop offset="0.5" stopColor="#f2a63a" />
          <stop offset="0.76" stopColor="#d9771f" />
          <stop offset="0.92" stopColor="#a84a16" />
          <stop offset="1" stopColor="#5e220c" />
        </radialGradient>
        <radialGradient id={`${id}-corner`} cx="58" cy="178" r="34" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#c9776f" stopOpacity="0.75" />
          <stop offset="1" stopColor="#c9776f" stopOpacity="0" />
        </radialGradient>
        <linearGradient id={`${id}-shade`} x1="0" y1="70" x2="0" y2="244" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#1a0808" stopOpacity="0.9" />
          <stop offset="0.22" stopColor="#1a0808" stopOpacity="0.42" />
          <stop offset="0.44" stopColor="#1a0808" stopOpacity="0" />
          <stop offset="0.86" stopColor="#1a0808" stopOpacity="0" />
          <stop offset="1" stopColor="#1a0808" stopOpacity="0.45" />
        </linearGradient>
        <linearGradient id={`${id}-lash`} x1="0" y1="56" x2="0" y2="150" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#5a2320" />
          <stop offset="0.45" stopColor="#2a0e0d" />
          <stop offset="1" stopColor="#100505" />
        </linearGradient>
        <radialGradient id={`${id}-glow`}>
          <stop offset="0" stopColor="#e7ae4c" stopOpacity="0.3" />
          <stop offset="0.45" stopColor="#c8413b" stopOpacity="0.08" />
          <stop offset="1" stopColor="#c8413b" stopOpacity="0" />
        </radialGradient>
      </defs>

      {glow && open ? <ellipse cx={CX} cy={156} rx={360} ry={180} fill={`url(#${id}-glow)`} /> : null}

      <g
        ref={body}
        style={{
          transformBox: "view-box",
          transformOrigin: `${CX}px 160px`,
          transform: open ? "scaleY(1)" : "scaleY(0.05)",
          opacity: open ? 1 : 0,
          transition: "transform 420ms cubic-bezier(.3,.7,.2,1), opacity 260ms ease",
        }}
      >
        <g clipPath={`url(#${id}-almond)`}>
          <rect x="20" y="60" width="620" height="200" fill={`url(#${id}-sclera)`} />
          <rect x="20" y="60" width="120" height="200" fill={`url(#${id}-corner)`} />
          <g ref={iris} transform={irisAt(look[0], look[1])}>
            <circle cx={CX} cy={CY} r={R} fill={`url(#${id}-iris)`} />
            <path d={fib.light} stroke="#fff3cf" strokeOpacity="0.16" strokeWidth="1.1" />
            <path d={fib.dark} stroke="#7a320f" strokeOpacity="0.22" strokeWidth="1.1" />
            {DARK_RINGS.map(([r, w]) => (
              <circle key={r} cx={CX} cy={CY} r={r} fill="none" stroke="#8f3510" strokeOpacity="0.78" strokeWidth={w} />
            ))}
            {LIGHT_RINGS.map((r) => (
              <circle key={r} cx={CX} cy={CY} r={r} fill="none" stroke="#ffe3a0" strokeOpacity="0.5" strokeWidth="2.2" />
            ))}
            <circle cx={CX} cy={CY} r={R - 4} fill="none" stroke="#3a1204" strokeOpacity="0.92" strokeWidth="8" />
            <circle cx={CX} cy={CY} r={28} fill="none" stroke="#7a2a0e" strokeWidth="3.5" />
            <circle cx={CX} cy={CY} r={20} fill="#170805" />
            <ellipse cx={CX - 36} cy={CY - 30} rx={20} ry={12} fill="#fff" opacity="0.88" transform={`rotate(-24 ${CX - 36} ${CY - 30})`} />
            <circle cx={CX + 40} cy={CY + 30} r={5} fill="#fff" opacity="0.45" />
          </g>
          <rect x="20" y="60" width="620" height="200" fill={`url(#${id}-shade)`} />
        </g>
        <path d={LOWER} fill="none" stroke="#3a1d18" strokeOpacity="0.6" strokeWidth="2.4" strokeLinecap="round" />
        <path d={LASH} fill={`url(#${id}-lash)`} />
      </g>
      {/* Shut, drawn in the text colour so it shows on either appearance. */}
      <g
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        style={{ opacity: open ? 0 : 1, transition: "opacity 260ms ease 120ms" }}
      >
        <path d={SHUT} strokeWidth="9" />
        <path d={SHUT_LASHES} strokeWidth="5" />
      </g>
    </svg>
  );
}
