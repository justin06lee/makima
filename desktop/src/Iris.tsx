/// makima's mark, alive: the ringed iris of the icon, with each ring turning
/// at its own pace while this device is on the network, and still and grey
/// while it is not. It is the status light in the title bar, the splash, and
/// the picture on the screens that have nothing else to show.
export function Iris({
  size = 24,
  state = "on",
  className = "",
}: {
  size?: number;
  state?: "on" | "off" | "busy";
  className?: string;
}) {
  const on = state !== "off";
  const ink = on ? "var(--ink)" : "var(--dimmer)";
  // Fine detail disappears at small sizes and only muddies the shape.
  const detailed = size >= 40;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      className={`shrink-0 overflow-visible ${className}`}
      role="img"
      aria-label={on ? "Connected" : "Not connected"}
    >
      {on && detailed && <circle cx="50" cy="50" r="30" fill="var(--accent)" opacity="0.08" />}

      {/* Outer ring and its eight marks, as on the icon. */}
      <g className={state === "busy" ? "turn-busy" : on ? "turn-slow" : ""}>
        <circle cx="50" cy="50" r="45" fill="none" stroke={ink} strokeWidth={detailed ? 1.6 : 5} opacity={on ? 0.9 : 0.7} />
        {detailed &&
          Array.from({ length: 8 }, (_, i) => {
            const a = (i * Math.PI) / 4;
            return (
              <line
                key={i}
                x1={50 + Math.cos(a) * 39}
                y1={50 + Math.sin(a) * 39}
                x2={50 + Math.cos(a) * 42}
                y2={50 + Math.sin(a) * 42}
                stroke={ink}
                strokeWidth="1.6"
                strokeLinecap="round"
              />
            );
          })}
      </g>

      {/* The middle ring, broken into dashes so its turning can be seen. */}
      <g className={on ? "turn-mid" : ""}>
        <circle
          cx="50"
          cy="50"
          r="32"
          fill="none"
          stroke={ink}
          strokeWidth={detailed ? 2.4 : 6}
          strokeDasharray={detailed ? "14 5" : undefined}
          opacity={on ? 1 : 0.7}
        />
      </g>

      <g className={on ? "turn-fast" : ""}>
        <circle
          cx="50"
          cy="50"
          r="18"
          fill="none"
          stroke={ink}
          strokeWidth={detailed ? 2 : 6}
          strokeDasharray={detailed ? "3 3.6" : undefined}
          opacity={on ? 1 : 0.7}
        />
      </g>

      <circle cx="50" cy="50" r={detailed ? 6.5 : 9} fill={on ? "var(--accent)" : "none"} stroke={on ? "none" : ink} strokeWidth="4" />
    </svg>
  );
}
