import { useEffect, useState } from "react";

// The small pieces every screen is built from, kept together so the app has
// one button rather than nine that are almost the same.

export function Button({
  children,
  onClick,
  tone = "quiet",
  busy,
  disabled,
  title,
}: {
  children: React.ReactNode;
  onClick?: () => void;
  tone?: "gold" | "crimson" | "quiet";
  busy?: boolean;
  disabled?: boolean;
  title?: string;
}) {
  const tones = {
    gold: "bg-gold/15 text-gold border-gold/40 hover:bg-gold/25",
    crimson: "bg-crimson/15 text-crimson border-crimson/40 hover:bg-crimson/25",
    quiet: "bg-panel-2 text-dim border-line-2 hover:text-ink hover:border-dim",
  }[tone];

  return (
    <button
      onClick={onClick}
      disabled={disabled || busy}
      title={title}
      className={`rounded-md border px-3 py-1.5 text-[13px] font-medium transition
        disabled:cursor-not-allowed disabled:opacity-45 ${tones}`}
    >
      {busy ? "…" : children}
    </button>
  );
}

/// A coloured dot. The only place in the app colour carries meaning on its
/// own, so it always sits beside a word that says the same thing.
export function Dot({ tone }: { tone: "green" | "gold" | "crimson" | "off" }) {
  const c = {
    green: "bg-green",
    gold: "bg-gold",
    crimson: "bg-crimson",
    off: "bg-dimmer",
  }[tone];
  return <span className={`inline-block size-2 shrink-0 rounded-full ${c}`} />;
}

export function Panel({
  title,
  right,
  children,
}: {
  title?: string;
  right?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-line bg-panel">
      {title && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          <h2 className="text-[11px] font-semibold uppercase tracking-wider text-dimmer">{title}</h2>
          {right}
        </header>
      )}
      <div>{children}</div>
    </section>
  );
}

/// Copy to the clipboard and say so for a moment.
///
/// The confirmation matters more than it looks: copying is silent, and without
/// it people click twice and wonder which one took.
export function useCopied(): [boolean, (text: string) => void] {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1400);
    return () => clearTimeout(t);
  }, [copied]);

  return [
    copied,
    async (text: string) => {
      const { writeText } = await import("@tauri-apps/plugin-clipboard-manager");
      await writeText(text);
      setCopied(true);
    },
  ];
}

export function Copyable({ value, className = "" }: { value: string; className?: string }) {
  const [copied, copy] = useCopied();
  return (
    <button
      onClick={() => copy(value)}
      title="Copy"
      className={`group inline-flex items-center gap-1.5 font-mono transition hover:text-ink ${className}`}
    >
      <span>{value}</span>
      <span
        className={`text-[10px] uppercase tracking-wide transition ${
          copied ? "text-green opacity-100" : "text-dimmer opacity-0 group-hover:opacity-100"
        }`}
      >
        {copied ? "copied" : "copy"}
      </span>
    </button>
  );
}
