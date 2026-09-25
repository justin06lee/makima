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
      strokeWidth="1.7"
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
  /// The network, drawn the way the Mesh page draws it: this device in the
  /// middle, the others on a ring.
  Mesh: (p: P) => (
    <Svg {...p}>
      <circle cx="12" cy="12" r="2.2" />
      <circle cx="12" cy="12" r="8.5" strokeDasharray="2 2.6" />
      <circle cx="12" cy="3.5" r="1.6" fill="currentColor" stroke="none" />
      <circle cx="19.4" cy="16.2" r="1.6" fill="currentColor" stroke="none" />
      <circle cx="4.6" cy="16.2" r="1.6" fill="currentColor" stroke="none" />
    </Svg>
  ),
  List: (p: P) => (
    <Svg {...p}>
      <path d="M9 6h11M9 12h11M9 18h11" />
      <circle cx="4.5" cy="6" r="1" fill="currentColor" />
      <circle cx="4.5" cy="12" r="1" fill="currentColor" />
      <circle cx="4.5" cy="18" r="1" fill="currentColor" />
    </Svg>
  ),
  Services: (p: P) => (
    <Svg {...p}>
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="1.5" />
      <path d="M17 14v6M14 17h6" />
    </Svg>
  ),
  Devices: (p: P) => (
    <Svg {...p}>
      <rect x="3" y="5" width="14" height="10" rx="1.5" />
      <path d="M3 18h12" />
      <rect x="18" y="9" width="4" height="9" rx="1" />
    </Svg>
  ),
  Laptop: (p: P) => (
    <Svg {...p}>
      <rect x="4.5" y="5" width="15" height="10" rx="1.5" />
      <path d="M2.5 19h19" />
    </Svg>
  ),
  Server: (p: P) => (
    <Svg {...p}>
      <rect x="4" y="4" width="16" height="7" rx="1.5" />
      <rect x="4" y="13" width="16" height="7" rx="1.5" />
      <path d="M8 7.5h.01M8 16.5h.01" strokeWidth="2.4" />
    </Svg>
  ),
  Exit: (p: P) => (
    <Svg {...p}>
      <circle cx="5" cy="17" r="2" />
      <circle cx="12" cy="8" r="2" />
      <path d="M6.3 15.4 10.7 9.6" />
      <path d="M13.8 7.2C16 6.4 18 5 20 3" />
      <path d="M16.5 3H20v3.5" />
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
  Send: (p: P) => (
    <Svg {...p}>
      <path d="M21 3 10.5 13.5" />
      <path d="M21 3 14.5 21l-4-7.5L3 9.5z" />
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
  ArrowRight: (p: P) => (
    <Svg {...p}>
      <path d="M4 12h16M14 6l6 6-6 6" />
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
  Shield: (p: P) => (
    <Svg {...p}>
      <path d="M12 3 5 6v6c0 4.2 3 7.6 7 9 4-1.4 7-4.8 7-9V6z" />
    </Svg>
  ),
  Power: (p: P) => (
    <Svg {...p}>
      <path d="M12 3v8" />
      <path d="M6.3 6.8a8 8 0 1 0 11.4 0" />
    </Svg>
  ),
  Relay: (p: P) => (
    <Svg {...p}>
      <circle cx="4.5" cy="12" r="2" />
      <circle cx="19.5" cy="12" r="2" />
      <path d="M6.5 12c2-4.5 9-4.5 11 0" strokeDasharray="2 2.4" />
      <circle cx="12" cy="8.6" r="1.6" fill="currentColor" stroke="none" />
    </Svg>
  ),
  Clock: (p: P) => (
    <Svg {...p}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </Svg>
  ),
  Command: (p: P) => (
    <Svg {...p}>
      <path d="M9 6v12M15 6v12M6 9h12M6 15h12" />
      <path d="M9 6a3 3 0 1 0-3 3M15 6a3 3 0 1 1 3 3M9 18a3 3 0 1 1-3-3M15 18a3 3 0 1 0 3-3" />
    </Svg>
  ),
  Info: (p: P) => (
    <Svg {...p}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5M12 8h.01" />
    </Svg>
  ),
  Warn: (p: P) => (
    <Svg {...p}>
      <path d="M12 3l10 18H2z" />
      <path d="M12 10v4M12 17.5v.5" />
    </Svg>
  ),
  Mark: (p: P) => (
    // The same circular iris as the native menu bar template.
    <svg width={p.size ?? 16} height={p.size ?? 16} viewBox="0 0 44 44" className={`shrink-0 ${p.className ?? ""}`} aria-hidden="true">
      <g fill="none" stroke="currentColor">
        <circle cx="22" cy="22" r="19" strokeWidth="2" />
        <circle cx="22" cy="22" r="14" strokeWidth="2.4" />
        <circle cx="22" cy="22" r="8" strokeWidth="2.2" />
        <path d="M22 4v2m0 32v2M4 22h2m32 0h2M9.3 9.3l1.4 1.4m22.6 22.6 1.4 1.4m0-25.4-1.4 1.4m-22.6 22.6-1.4 1.4" strokeWidth="1.6" />
      </g>
      <circle cx="22" cy="22" r="2.7" fill="currentColor" />
    </svg>
  ),
};
