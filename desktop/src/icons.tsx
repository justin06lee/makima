// Line icons, drawn once on a 24px grid. They render at 16px by default and
// take the text colour, so an icon is never a different grey from its label.

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
  Devices: (p: P) => (
    <Svg {...p}>
      <rect x="2.5" y="4.5" width="15" height="10.5" rx="2" />
      <path d="M6 19h8" />
      <rect x="19" y="8.5" width="3" height="10.5" rx="1" />
    </Svg>
  ),
  Services: (p: P) => (
    <Svg {...p}>
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.8" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="1.8" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="1.8" />
      <path d="M17 13.5v7M13.5 17h7" />
    </Svg>
  ),
  Exit: (p: P) => (
    <Svg {...p}>
      <circle cx="12" cy="12" r="9" />
      <path d="M3.5 9h17M3.5 15h17" />
      <path d="M12 3c2.4 2.5 3.6 5.5 3.6 9s-1.2 6.5-3.6 9c-2.4-2.5-3.6-5.5-3.6-9S9.6 5.5 12 3z" />
    </Svg>
  ),
  Gear: (p: P) => (
    <Svg {...p}>
      <path d="M12 15.2a3.2 3.2 0 1 0 0-6.4 3.2 3.2 0 0 0 0 6.4z" />
      <path d="M19.4 13.6a7.9 7.9 0 0 0 0-3.2l2-1.5-2-3.5-2.4 1a7.7 7.7 0 0 0-2.7-1.6L14 2.3h-4l-.3 2.5A7.7 7.7 0 0 0 7 6.4l-2.4-1-2 3.5 2 1.5a7.9 7.9 0 0 0 0 3.2l-2 1.5 2 3.5 2.4-1a7.7 7.7 0 0 0 2.7 1.6l.3 2.5h4l.3-2.5a7.7 7.7 0 0 0 2.7-1.6l2.4 1 2-3.5z" />
    </Svg>
  ),
  Plus: (p: P) => (
    <Svg {...p}>
      <path d="M12 5v14M5 12h14" />
    </Svg>
  ),
  Search: (p: P) => (
    <Svg {...p}>
      <circle cx="11" cy="11" r="6.5" />
      <path d="M20 20l-4.2-4.2" />
    </Svg>
  ),
  Copy: (p: P) => (
    <Svg {...p}>
      <rect x="8.5" y="8.5" width="12" height="12" rx="2.5" />
      <path d="M15.5 8.5V6a2.5 2.5 0 0 0-2.5-2.5H6A2.5 2.5 0 0 0 3.5 6v7A2.5 2.5 0 0 0 6 15.5h2.5" />
    </Svg>
  ),
  Check: (p: P) => (
    <Svg {...p}>
      <path d="M5 12.5l4.5 4.5L19 7" />
    </Svg>
  ),
  Terminal: (p: P) => (
    <Svg {...p}>
      <rect x="2.5" y="4" width="19" height="16" rx="2.5" />
      <path d="M7 9.5l3 2.5-3 2.5M12.5 15h4.5" />
    </Svg>
  ),
  Pulse: (p: P) => (
    <Svg {...p}>
      <path d="M3 12h4l2.5-6 5 12 2.5-6h4" />
    </Svg>
  ),
  Send: (p: P) => (
    <Svg {...p}>
      <path d="M12 15V3.5M7.5 8L12 3.5 16.5 8" />
      <path d="M4 14.5v3A2.5 2.5 0 0 0 6.5 20h11a2.5 2.5 0 0 0 2.5-2.5v-3" />
    </Svg>
  ),
  Upload: (p: P) => (
    <Svg {...p}>
      <path d="M12 15V3.5M7.5 8L12 3.5 16.5 8" />
      <path d="M4 14.5v3A2.5 2.5 0 0 0 6.5 20h11a2.5 2.5 0 0 0 2.5-2.5v-3" />
    </Svg>
  ),
  Inbox: (p: P) => (
    <Svg {...p}>
      <path d="M3.5 13.5l2.6-7.3A2 2 0 0 1 8 5h8a2 2 0 0 1 1.9 1.2l2.6 7.3" />
      <path d="M3.5 13.5V18a2 2 0 0 0 2 2h13a2 2 0 0 0 2-2v-4.5h-5a3 3 0 0 1-6 0z" />
    </Svg>
  ),
  Close: (p: P) => (
    <Svg {...p}>
      <path d="M6.5 6.5l11 11M17.5 6.5l-11 11" />
    </Svg>
  ),
  Chevron: (p: P) => (
    <Svg {...p}>
      <path d="M9.5 6l6 6-6 6" />
    </Svg>
  ),
  ChevronDown: (p: P) => (
    <Svg {...p}>
      <path d="M6 9.5l6 6 6-6" />
    </Svg>
  ),
  Back: (p: P) => (
    <Svg {...p}>
      <path d="M14.5 6l-6 6 6 6" />
    </Svg>
  ),
  Folder: (p: P) => (
    <Svg {...p}>
      <path d="M3.5 7.5A2 2 0 0 1 5.5 5.5h3.6l2 2h7.4a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z" />
    </Svg>
  ),
  Open: (p: P) => (
    <Svg {...p}>
      <path d="M8 16L16 8M9.5 8H16v6.5" />
    </Svg>
  ),
  Globe: (p: P) => (
    <Svg {...p}>
      <circle cx="12" cy="12" r="9" />
      <path d="M3.5 9h17M3.5 15h17" />
      <path d="M12 3c2.4 2.5 3.6 5.5 3.6 9s-1.2 6.5-3.6 9c-2.4-2.5-3.6-5.5-3.6-9S9.6 5.5 12 3z" />
    </Svg>
  ),
  Key: (p: P) => (
    <Svg {...p}>
      <circle cx="8" cy="15" r="4.5" />
      <path d="M11.2 11.8L20 3M16.5 6.5l2.5 2.5M14 9l2 2" />
    </Svg>
  ),
  Warn: (p: P) => (
    <Svg {...p}>
      <path d="M10.3 4.1L2.7 17.5A2 2 0 0 0 4.4 20.5h15.2a2 2 0 0 0 1.7-3L13.7 4.1a2 2 0 0 0-3.4 0z" />
      <path d="M12 9.5v4M12 17h.01" />
    </Svg>
  ),
  Power: (p: P) => (
    <Svg {...p}>
      <path d="M12 3v8.5" />
      <path d="M17.7 6.8a8 8 0 1 1-11.4 0" />
    </Svg>
  ),
  Command: (p: P) => (
    <Svg {...p}>
      <path d="M9 9V6.5A2.5 2.5 0 1 0 6.5 9H9zm0 0h6m-6 0v6m6-6V6.5A2.5 2.5 0 1 1 17.5 9H15zm0 0v6m0 0h2.5a2.5 2.5 0 1 1-2.5 2.5V15zm0 0H9m0 0v2.5A2.5 2.5 0 1 1 6.5 15H9z" />
    </Svg>
  ),
  More: (p: P) => (
    <Svg {...p}>
      <circle cx="5.5" cy="12" r="0.6" fill="currentColor" />
      <circle cx="12" cy="12" r="0.6" fill="currentColor" />
      <circle cx="18.5" cy="12" r="0.6" fill="currentColor" />
    </Svg>
  ),
  Arrow: (p: P) => (
    <Svg {...p}>
      <path d="M4.5 12h15M13.5 6l6 6-6 6" />
    </Svg>
  ),
  Shield: (p: P) => (
    <Svg {...p}>
      <path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.2-7.5 9.5-4.3-1.3-7.5-4.9-7.5-9.5V6z" />
    </Svg>
  ),
  Refresh: (p: P) => (
    <Svg {...p}>
      <path d="M20 11a8 8 0 0 0-14.3-4.3L4 8.5M4 4v4.5h4.5" />
      <path d="M4 13a8 8 0 0 0 14.3 4.3L20 15.5M20 20v-4.5h-4.5" />
    </Svg>
  ),
  Home: (p: P) => (
    <Svg {...p}>
      <path d="M4 10.5L12 4l8 6.5V19a1.5 1.5 0 0 1-1.5 1.5H15V15h-6v5.5H5.5A1.5 1.5 0 0 1 4 19z" />
    </Svg>
  ),
  Swap: (p: P) => (
    <Svg {...p}>
      <path d="M4 8h14.5M15 4.5L18.5 8 15 11.5" />
      <path d="M20 16H5.5M9 12.5L5.5 16 9 19.5" />
    </Svg>
  ),
  Pencil: (p: P) => (
    <Svg {...p}>
      <path d="M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16z" />
      <path d="M13.5 6.5l4 4" />
    </Svg>
  ),
  Plug: (p: P) => (
    <Svg {...p}>
      <path d="M9 3.5V7M15 3.5V7" />
      <path d="M6.5 7h11v3.5a5.5 5.5 0 0 1-11 0z" />
      <path d="M12 16v4.5" />
    </Svg>
  ),
  Link: (p: P) => (
    <Svg {...p}>
      <path d="M10 14a4 4 0 0 0 5.7 0l3.1-3.1a4 4 0 0 0-5.7-5.7l-1 1" />
      <path d="M14 10a4 4 0 0 0-5.7 0l-3.1 3.1a4 4 0 0 0 5.7 5.7l1-1" />
    </Svg>
  ),
};
