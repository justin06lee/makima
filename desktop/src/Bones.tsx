import { f, rng } from "./pen";

/// The wordmark, spelled in bones: the website's, drawn the same way.
///
/// A nod to the Hell Devil chapter of Chainsaw Man, where the arms thrown up
/// into the air happen to spell out MAKIMA. Every stroke is one bone, set
/// down a little off true, lit from the upper left, with a soft shadow and a
/// red glow under it whose strength the stylesheet sets per appearance.

type Stroke = [number, number, number, number];

const TOP = 24;
const BASE = 156;
const VEE = 110;
const BAR = 110;

const WORD: Stroke[] = [
  [22, BASE, 22, TOP],
  [22, TOP, 72, VEE],
  [72, VEE, 122, TOP],
  [122, TOP, 122, BASE],
  [160, BASE, 207, TOP],
  [207, TOP, 254, BASE],
  [182, BAR, 232, BAR],
  [292, TOP, 292, BASE],
  [298, 92, 360, TOP],
  [304, 84, 366, BASE],
  [404, TOP, 404, BASE],
  [442, BASE, 442, TOP],
  [442, TOP, 492, VEE],
  [492, VEE, 542, TOP],
  [542, TOP, 542, BASE],
  [580, BASE, 627, TOP],
  [627, TOP, 674, BASE],
  [602, BAR, 652, BAR],
];

const LIGHT = { x: -0.55, y: -0.83 };
const R = 10;
const D = 6.6;
const W = 5.4;

function outline(len: number): string {
  const s = Math.sqrt(R * R - D * D);
  const j = R + Math.sqrt(R * R - (D - W) ** 2);
  const mid = len / 2;
  const waist = W * 0.72;
  return (
    `M${f(j)} ${f(-W)}` +
    `Q${f(mid)} ${f(-waist)} ${f(len - j)} ${f(-W)}` +
    `A${R} ${R} 0 1 1 ${f(len - R + s)} 0` +
    `A${R} ${R} 0 1 1 ${f(len - j)} ${f(W)}` +
    `Q${f(mid)} ${f(waist)} ${f(j)} ${f(W)}` +
    `A${R} ${R} 0 1 1 ${f(R - s)} 0` +
    `A${R} ${R} 0 1 1 ${f(j)} ${f(-W)}Z`
  );
}

const BONES = (() => {
  const rand = rng(1917);
  return WORD.map(([x1, y1, x2, y2]) => {
    const jitter = () => (rand() - 0.5) * 5;
    const ax = x1 + jitter();
    const ay = y1 + jitter();
    const bx = x2 + jitter();
    const by = y2 + jitter();
    const len = Math.hypot(bx - ax, by - ay);
    const th = Math.atan2(by - ay, bx - ax);
    const topLit = Math.sin(th) * LIGHT.x - Math.cos(th) * LIGHT.y > 0;
    const j = R + Math.sqrt(R * R - (D - W) ** 2);
    const edge = (topLit ? -1 : 1) * 3.1;
    return {
      at: `translate(${f(ax)} ${f(ay)}) rotate(${f((th * 180) / Math.PI)})`,
      d: outline(len),
      fill: topLit ? "url(#bone-lit-top)" : "url(#bone-lit-bottom)",
      shine: `M${f(j + 3)} ${f(edge)}Q${f(len / 2)} ${f(edge * 0.7)} ${f(len - j - 3)} ${f(edge)}`,
      delay: Math.round(rand() * 140),
    };
  });
})();

export function Bones({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 4 690 180" className={`bones overflow-visible ${className}`} aria-hidden="true">
      <defs>
        <linearGradient id="bone-lit-top" x1="0" y1="-17" x2="0" y2="17" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#fbf4e4" />
          <stop offset="0.32" stopColor="#eadcc1" />
          <stop offset="0.72" stopColor="#c9b28c" />
          <stop offset="1" stopColor="#8b7353" />
        </linearGradient>
        <linearGradient id="bone-lit-bottom" x1="0" y1="17" x2="0" y2="-17" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#fbf4e4" />
          <stop offset="0.32" stopColor="#eadcc1" />
          <stop offset="0.72" stopColor="#c9b28c" />
          <stop offset="1" stopColor="#8b7353" />
        </linearGradient>
        <filter id="bone-shadow" x="-10%" y="-20%" width="120%" height="160%">
          <feGaussianBlur stdDeviation="4.5" />
        </filter>
      </defs>
      <g filter="url(#bone-shadow)">
        <g fill="#000" style={{ opacity: "var(--bone-shadow)" }}>
          {BONES.map((b, i) => (
            <path key={i} d={b.d} transform={`translate(5 10) ${b.at}`} />
          ))}
        </g>
        <g fill="#c8413b" style={{ opacity: "var(--bone-glow)" }}>
          {BONES.map((b, i) => (
            <path key={i} d={b.d} transform={`translate(0 16) ${b.at}`} />
          ))}
        </g>
      </g>
      {BONES.map((b, i) => (
        <g key={i} transform={b.at}>
          <g className="bone" style={{ animationDelay: `${b.delay}ms` }}>
            <path d={b.d} fill={b.fill} stroke="#241910" strokeOpacity="0.7" strokeWidth="1.4" strokeLinejoin="round" />
            <path d={b.shine} fill="none" stroke="#fffaf0" strokeOpacity="0.6" strokeWidth="1.6" strokeLinecap="round" />
          </g>
        </g>
      ))}
    </svg>
  );
}
