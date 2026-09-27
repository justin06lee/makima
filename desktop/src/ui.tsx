import { useEffect, useState } from "react";
import { copyText } from "./api";
import { Icon } from "./icons";

// The small pieces every screen is built from, kept together so the app has
// one button rather than nine that are almost the same.

export function Button({
  children,
  onClick,
  variant = "default",
  size = "md",
  busy,
  disabled,
  title,
  icon,
  className = "",
  type = "button",
}: {
  children?: React.ReactNode;
  onClick?: () => void;
  variant?: "primary" | "default" | "danger" | "ghost";
  size?: "sm" | "md" | "lg";
  busy?: boolean;
  disabled?: boolean;
  title?: string;
  icon?: React.ReactNode;
  className?: string;
  type?: "button" | "submit";
}) {
  const variants = {
    primary: "bg-accent text-accent-ink border-transparent hover:brightness-110 active:brightness-95 shadow-[inset_0_1px_0_rgba(255,255,255,0.15)]",
    default: "bg-bg text-ink border-line-2 hover:bg-card active:bg-card-2 shadow-[0_1px_1px_rgba(0,0,0,0.04)]",
    danger: "bg-bg text-red border-line-2 hover:bg-card active:bg-card-2",
    ghost: "bg-transparent text-dim border-transparent hover:bg-card hover:text-ink",
  }[variant];
  const sizes = {
    sm: "h-6 px-2 text-[12px] gap-1 rounded-md",
    md: "h-7 px-3 text-[13px] gap-1.5 rounded-lg",
    lg: "h-9 px-4 text-[14px] gap-2 rounded-lg",
  }[size];

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || busy}
      title={title}
      className={`inline-flex shrink-0 items-center justify-center border font-medium transition
        disabled:cursor-not-allowed disabled:opacity-50 ${variants} ${sizes} ${className}`}
    >
      {busy ? <Spinner /> : icon}
      {children}
    </button>
  );
}

export function IconButton({
  children,
  onClick,
  title,
  active,
  busy,
}: {
  children: React.ReactNode;
  onClick?: () => void;
  title: string;
  active?: boolean;
  busy?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      aria-label={title}
      disabled={busy}
      className={`inline-flex size-7 items-center justify-center rounded-lg border border-transparent transition
        hover:bg-card active:bg-card-2 disabled:opacity-50 ${active ? "bg-card text-ink" : "text-dim hover:text-ink"}`}
    >
      {busy ? <Spinner /> : children}
    </button>
  );
}

export function Spinner({ className = "" }: { className?: string }) {
  return (
    <svg className={`spin size-3.5 ${className}`} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

/// The switch. On is blue, like every other switch on the platform.
export function Toggle({
  on,
  onChange,
  busy,
  disabled,
  label,
  size = "md",
}: {
  on: boolean;
  onChange: (next: boolean) => void;
  busy?: boolean;
  disabled?: boolean;
  label: string;
  size?: "md" | "lg";
}) {
  const dims = size === "lg" ? "h-[26px] w-[44px]" : "h-[22px] w-[38px]";
  const knob = size === "lg" ? "size-[22px]" : "size-[18px]";
  const travel = size === "lg" ? "translate-x-[18px]" : "translate-x-[16px]";
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      title={label}
      disabled={disabled || busy}
      onClick={() => onChange(!on)}
      className={`relative inline-flex shrink-0 items-center rounded-full border transition-colors duration-200
        disabled:cursor-not-allowed ${dims}
        ${on ? "border-transparent bg-accent" : "border-line-2 bg-card-2"}
        ${busy ? "opacity-70" : ""}`}
    >
      <span
        className={`absolute left-[1px] inline-flex items-center justify-center rounded-full bg-white shadow-[0_1px_3px_rgba(0,0,0,0.35)] transition-transform duration-200 ${knob}
          ${on ? travel : "translate-x-0"}`}
      >
        {busy && <Spinner className="text-dim" />}
      </span>
    </button>
  );
}

/// A coloured dot. The only place in the app colour carries meaning on its
/// own, so it always sits beside a word that says the same thing.
export function Dot({ tone, size = "md" }: { tone: "green" | "grey" | "amber" | "red"; size?: "sm" | "md" }) {
  const c = { green: "bg-green", grey: "bg-grey", amber: "bg-amber", red: "bg-red" }[tone];
  const s = size === "sm" ? "size-1.5" : "size-2";
  return <span className={`inline-block shrink-0 rounded-full ${s} ${c}`} />;
}

/// A rounded group of rows, like the address cards on the platform's own
/// settings screens.
export function Card({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <div className={`overflow-hidden rounded-xl bg-card ${className}`}>{children}</div>;
}

/// One row in a Card: a value with a caption beneath it, and room on the
/// right for whatever acts on it.
export function Row({
  value,
  caption,
  right,
  mono,
  onClick,
  title,
}: {
  value: React.ReactNode;
  caption?: React.ReactNode;
  right?: React.ReactNode;
  mono?: boolean;
  onClick?: () => void;
  title?: string;
}) {
  const inner = (
    <>
      <div className="min-w-0 flex-1">
        <div className={`truncate text-[14px] text-ink ${mono ? "font-mono text-[13px]" : ""}`}>{value}</div>
        {caption && <div className="mt-0.5 truncate text-[12px] text-dim">{caption}</div>}
      </div>
      {right && <div className="flex shrink-0 items-center gap-1.5">{right}</div>}
    </>
  );
  const cls = "flex items-center gap-3 border-b border-line px-4 py-2.5 last:border-0";
  if (onClick) {
    return (
      <button type="button" onClick={onClick} title={title} className={`${cls} w-full text-left transition hover:bg-card-2`}>
        {inner}
      </button>
    );
  }
  return <div className={cls}>{inner}</div>;
}

export function Section({ title, right, children }: { title: string; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="space-y-2">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-[15px] font-medium text-dim">{title}</h3>
        {right}
      </div>
      {children}
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
      await copyText(text);
      setCopied(true);
    },
  ];
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, copy] = useCopied();
  return (
    <IconButton onClick={() => copy(value)} title={copied ? "Copied" : label}>
      {copied ? <Icon.Check className="text-green" /> : <Icon.Copy />}
    </IconButton>
  );
}

export function Search({ value, onChange, placeholder = "Search…" }: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <label className="relative block">
      <Icon.Search className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-dimmer" />
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        spellCheck={false}
        className="selectable h-8 w-full rounded-lg border border-transparent bg-card pl-8 pr-3 text-[13px] text-ink outline-none placeholder:text-dimmer focus:border-accent/40 focus:bg-bg"
      />
    </label>
  );
}

export function Input({
  value,
  onChange,
  placeholder,
  mono,
  onEnter,
  autoFocus,
  className = "",
  inputMode,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  mono?: boolean;
  onEnter?: () => void;
  autoFocus?: boolean;
  className?: string;
  inputMode?: "numeric" | "text";
}) {
  return (
    <input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={(e) => e.key === "Enter" && onEnter?.()}
      placeholder={placeholder}
      autoFocus={autoFocus}
      spellCheck={false}
      autoCapitalize="off"
      autoCorrect="off"
      inputMode={inputMode}
      className={`selectable h-8 w-full rounded-lg border border-line-2 bg-bg px-3 text-[13px] text-ink outline-none
        placeholder:text-dimmer focus:border-accent ${mono ? "font-mono text-[12px]" : ""} ${className}`}
    />
  );
}

/// A sheet over the window. One at a time, closed by the button or Escape.
export function Modal({ title, onClose, children, width = "max-w-[460px]" }: { title: string; onClose: () => void; children: React.ReactNode; width?: string }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/30 p-6" onMouseDown={onClose}>
      <div
        role="dialog"
        aria-label={title}
        onMouseDown={(e) => e.stopPropagation()}
        className={`fade-in w-full ${width} rounded-2xl bg-bg p-5 shadow-[var(--shadow)]`}
      >
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-[16px] font-semibold">{title}</h2>
          <IconButton onClick={onClose} title="Close">
            <Icon.Close />
          </IconButton>
        </div>
        {children}
      </div>
    </div>
  );
}

/// Something went wrong, in one line, until dismissed.
export function Notice({ text, onDismiss }: { text: string; onDismiss: () => void }) {
  return (
    <div className="fade-in flex items-start gap-2.5 border-b border-red/20 bg-red/8 px-4 py-2.5">
      <Icon.Warn className="mt-px text-red" />
      <p className="selectable flex-1 text-[12.5px] leading-relaxed text-ink">{text}</p>
      <IconButton onClick={onDismiss} title="Dismiss">
        <Icon.Close />
      </IconButton>
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="flex h-full flex-col items-center justify-center px-8 text-center">
      <p className="text-[14px] font-medium text-ink">{title}</p>
      {children && <div className="mt-1.5 max-w-xs text-[13px] leading-relaxed text-dim">{children}</div>}
    </div>
  );
}

export function Code({ children }: { children: string }) {
  return (
    <code className="selectable block break-all rounded-lg bg-card px-3 py-2 font-mono text-[12px] leading-relaxed text-ink">
      {children}
    </code>
  );
}
