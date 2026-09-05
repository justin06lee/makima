// Line icons, drawn once. 16px, stroke follows the text colour.

type P = { className?: string; size?: number };

function Svg({ children, className = "", size = 16 }: P & { children: React.ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={`shrink-0 ${className}`}
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

export const Icon = {
  Devices: (p: P) => (
    <Svg {...p}>
      <rect x="3" y="5" width="14" height="10" rx="1.5" />
      <path d="M3 18h12" />
      <rect x="18" y="9" width="4" height="9" rx="1" />
    </Svg>
  ),
  Exit: (p: P) => (
    <Svg {...p}>
      <path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4" />
      <path d="M10 8l4 4-4 4" />
      <path d="M14 12H3" />
    </Svg>
  ),
  Gear: (p: P) => (
    <Svg {...p}>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
    </Svg>
  ),
  Plus: (p: P) => (
    <Svg {...p}>
      <path d="M12 5v14M5 12h14" />
    </Svg>
  ),
  Search: (p: P) => (
    <Svg {...p}>
      <circle cx="11" cy="11" r="7" />
      <path d="M20 20l-3.5-3.5" />
    </Svg>
  ),
  Copy: (p: P) => (
    <Svg {...p}>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5 15V6a2 2 0 0 1 2-2h9" />
    </Svg>
  ),
  Check: (p: P) => (
    <Svg {...p}>
      <path d="M5 12.5l4.5 4.5L19 7" />
    </Svg>
  ),
  Terminal: (p: P) => (
    <Svg {...p}>
      <path d="M5 7l5 5-5 5" />
      <path d="M12 19h7" />
    </Svg>
  ),
  Pulse: (p: P) => (
    <Svg {...p}>
      <path d="M3 12h4l3-7 4 14 3-7h4" />
    </Svg>
  ),
  Upload: (p: P) => (
    <Svg {...p}>
      <path d="M12 16V4" />
      <path d="M7 9l5-5 5 5" />
      <path d="M4 20h16" />
    </Svg>
  ),
  Close: (p: P) => (
    <Svg {...p}>
      <path d="M6 6l12 12M18 6L6 18" />
    </Svg>
  ),
  Chevron: (p: P) => (
    <Svg {...p}>
      <path d="M9 6l6 6-6 6" />
    </Svg>
  ),
  Folder: (p: P) => (
    <Svg {...p}>
      <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
    </Svg>
  ),
  Open: (p: P) => (
    <Svg {...p}>
      <path d="M7 17L17 7" />
      <path d="M9 7h8v8" />
    </Svg>
  ),
  Globe: (p: P) => (
    <Svg {...p}>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" />
    </Svg>
  ),
  Key: (p: P) => (
    <Svg {...p}>
      <circle cx="8" cy="14" r="4" />
      <path d="M11 11l9-9M16 6l3 3M13 9l2 2" />
    </Svg>
  ),
  Warn: (p: P) => (
    <Svg {...p}>
      <path d="M12 3l10 18H2z" />
      <path d="M12 10v4M12 17.5v.5" />
    </Svg>
  ),
  Mark: (p: P) => (
    // makima's own mark: three nodes around a centre, the banner reduced.
    <svg width={p.size ?? 16} height={p.size ?? 16} viewBox="0 0 44 44" className={`shrink-0 ${p.className ?? ""}`} aria-hidden="true">
      <path d="M22 8 L35 30 L9 30 Z" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinejoin="round" />
      <g fill="currentColor">
        <circle cx="22" cy="8" r="4.2" />
        <circle cx="35" cy="30" r="4.2" />
        <circle cx="9" cy="30" r="4.2" />
        <circle cx="22" cy="23" r="4.6" />
      </g>
    </svg>
  ),
};
