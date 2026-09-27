import { useEffect, useState } from "react";
import { Icon } from "./icons";
import { useCopy } from "./toast";

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
  kbd,
  className = "",
  type = "button",
}: {
  children?: React.ReactNode;
  onClick?: () => void;
  variant?: "primary" | "default" | "danger" | "ghost" | "ink";
  size?: "sm" | "md" | "lg";
  busy?: boolean;
  disabled?: boolean;
  title?: string;
  icon?: React.ReactNode;
  /// A keyboard shortcut to show on the button, like ⌘N.
  kbd?: string;
  className?: string;
  type?: "button" | "submit";
}) {
  const variants = {
    primary:
      "bg-accent text-accent-ink border-transparent hover:bg-accent-2 shadow-[inset_0_1px_0_rgba(255,255,255,0.18),0_1px_2px_rgba(0,0,0,0.12)]",
    ink: "bg-ink text-bg border-transparent hover:opacity-90",
    default: "bg-raised text-ink border-line-2 hover:bg-raised-2 hover:border-dimmer/50 shadow-[0_1px_1px_rgba(0,0,0,0.04)]",
    danger: "bg-raised text-red border-line-2 hover:bg-red/8 hover:border-red/40",
    ghost: "bg-transparent text-dim border-transparent hover:bg-ink/6 hover:text-ink",
  }[variant];
  const sizes = {
    sm: "h-[26px] px-2.5 text-[12px] gap-1.5 rounded-md",
    md: "h-[30px] px-3 text-[13px] gap-1.5 rounded-lg",
    lg: "h-10 px-5 text-[14px] gap-2 rounded-xl",
  }[size];

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || busy}
      title={title}
      className={`inline-flex shrink-0 select-none items-center justify-center border font-medium transition-[background,border,opacity,transform] duration-150
        active:translate-y-px disabled:cursor-not-allowed disabled:opacity-45 disabled:active:translate-y-0 ${variants} ${sizes} ${className}`}
    >
      {busy ? <Spinner /> : icon}
      {children}
      {kbd && <Kbd className={variant === "primary" ? "!border-white/25 !bg-white/15 !text-white/85" : ""}>{kbd}</Kbd>}
    </button>
  );
}

export function IconButton({
  children,
  onClick,
  title,
  active,
  busy,
  size = "md",
}: {
  children: React.ReactNode;
  onClick?: () => void;
  title: string;
  active?: boolean;
  busy?: boolean;
  size?: "sm" | "md";
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      aria-label={title}
      disabled={busy}
      className={`inline-flex ${size === "sm" ? "size-6 rounded-md" : "size-[30px] rounded-lg"} shrink-0 items-center justify-center transition
        hover:bg-ink/6 active:bg-ink/10 disabled:opacity-50 ${active ? "bg-ink/8 text-ink" : "text-dim hover:text-ink"}`}
    >
      {busy ? <Spinner /> : children}
    </button>
  );
}

export function Kbd({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <kbd
      className={`inline-flex h-[18px] min-w-[18px] items-center justify-center rounded-[5px] border border-line-2 bg-raised-2 px-1 font-sans text-[10.5px] font-medium text-dim ${className}`}
    >
      {children}
    </kbd>
  );
}

export function Spinner({ className = "" }: { className?: string }) {
  return (
    <svg className={`spin size-3.5 ${className}`} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.2" strokeWidth="2.6" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" />
    </svg>
  );
}

/// The switch. On is makima's red: the one colour that means "live".
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
  const dims = size === "lg" ? "h-[24px] w-[42px]" : "h-[20px] w-[34px]";
  const knob = size === "lg" ? "size-[18px]" : "size-[14px]";
  const travel = size === "lg" ? "translate-x-[18px]" : "translate-x-[14px]";
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      title={label}
      disabled={disabled || busy}
      onClick={() => onChange(!on)}
      className={`relative inline-flex shrink-0 items-center rounded-full transition-colors duration-200
        disabled:cursor-not-allowed ${dims}
        ${on ? "bg-accent shadow-[inset_0_1px_2px_rgba(0,0,0,0.2)]" : "bg-line-2 shadow-[inset_0_1px_2px_rgba(0,0,0,0.12)]"}
        ${busy ? "opacity-70" : ""} ${disabled && !busy ? "opacity-45" : ""}`}
    >
      <span
        className={`absolute left-[3px] inline-flex items-center justify-center rounded-full bg-white shadow-[0_1px_3px_rgba(0,0,0,0.35)] transition-transform duration-200 ease-[cubic-bezier(0.3,1.4,0.5,1)] ${knob}
          ${on ? travel : "translate-x-0"}`}
      >
        {busy && <Spinner className="!size-2.5 text-dim" />}
      </span>
    </button>
  );
}

/// A coloured dot. Colour carries meaning here, so it always sits beside a
/// word that says the same thing. A live dot breathes.
export function Dot({ tone, size = "md", live }: { tone: "green" | "grey" | "amber" | "red" | "accent"; size?: "sm" | "md"; live?: boolean }) {
  const c = { green: "bg-green", grey: "bg-grey", amber: "bg-amber", red: "bg-red", accent: "bg-accent" }[tone];
  const s = size === "sm" ? "size-1.5" : "size-2";
  return (
    <span className={`relative inline-flex shrink-0 ${s}`}>
      {live && <span className={`ping-ring absolute inset-0 rounded-full ${c}`} />}
      <span className={`relative inline-block rounded-full ${s} ${c}`} />
    </span>
  );
}

/// A raised group of rows.
export function Card({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <div className={`overflow-hidden rounded-xl bg-raised shadow-[var(--shadow-sm)] ${className}`}>{children}</div>;
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
  icon,
}: {
  value: React.ReactNode;
  caption?: React.ReactNode;
  right?: React.ReactNode;
  mono?: boolean;
  onClick?: () => void;
  title?: string;
  icon?: React.ReactNode;
}) {
  const inner = (
    <>
      {icon && <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-raised-2 text-dim">{icon}</span>}
      <div className="min-w-0 flex-1">
        <div className={`truncate text-[13.5px] text-ink ${mono ? "font-mono text-[12.5px]" : ""}`}>{value}</div>
        {caption && <div className="mt-0.5 text-[12px] leading-snug text-dim">{caption}</div>}
      </div>
      {right && <div className="flex shrink-0 items-center gap-1.5">{right}</div>}
    </>
  );
  const cls = "flex items-center gap-3 border-b border-line px-4 py-3 last:border-0";
  if (onClick) {
    return (
      <button type="button" onClick={onClick} title={title} className={`${cls} w-full text-left transition hover:bg-raised-2`}>
        {inner}
      </button>
    );
  }
  return <div className={cls}>{inner}</div>;
}

export function Section({ title, right, children, hint }: { title: string; right?: React.ReactNode; children: React.ReactNode; hint?: React.ReactNode }) {
  return (
    <section className="space-y-2.5">
      <div className="flex min-h-[26px] items-center justify-between gap-3">
        <h3 className="caps text-dimmer">{title}</h3>
        {right}
      </div>
      {children}
      {hint && <p className="px-1 text-[12px] leading-relaxed text-dimmer">{hint}</p>}
    </section>
  );
}

/// A label that copies what it shows when clicked, and says so.
export function Copyable({ value, what, className = "", children }: { value: string; what?: string; className?: string; children?: React.ReactNode }) {
  const copy = useCopy();
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        void copy(value, what);
      }}
      title={`Copy ${what ?? value}`}
      className={`group/copy inline-flex max-w-full items-center gap-1.5 rounded-md text-left transition hover:text-ink ${className}`}
    >
      <span className="truncate">{children ?? value}</span>
      <Icon.Copy size={12} className="opacity-0 transition group-hover/copy:opacity-60" />
    </button>
  );
}

export function CopyButton({ value, label = "Copy", what }: { value: string; label?: string; what?: string }) {
  const copy = useCopy();
  return (
    <IconButton onClick={() => copy(value, what)} title={label}>
      <Icon.Copy />
    </IconButton>
  );
}

export function Search({
  value,
  onChange,
  placeholder = "Search…",
  autoFocus,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  autoFocus?: boolean;
}) {
  return (
    <label className="relative block">
      <Icon.Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-dimmer" />
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        autoFocus={autoFocus}
        spellCheck={false}
        className="selectable h-[30px] w-full rounded-lg border border-line bg-raised pl-8 pr-3 text-[13px] text-ink outline-none transition placeholder:text-dimmer focus:border-accent/50"
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
  type = "text",
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  mono?: boolean;
  onEnter?: () => void;
  autoFocus?: boolean;
  className?: string;
  inputMode?: "numeric" | "text";
  type?: "text" | "password";
}) {
  return (
    <input
      type={type}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={(e) => e.key === "Enter" && onEnter?.()}
      placeholder={placeholder}
      autoFocus={autoFocus}
      spellCheck={false}
      autoCapitalize="off"
      autoCorrect="off"
      inputMode={inputMode}
      className={`selectable h-[30px] w-full rounded-lg border border-line-2 bg-raised px-3 text-[13px] text-ink outline-none transition
        placeholder:text-dimmer focus:border-accent/60 ${mono ? "font-mono text-[12px]" : ""} ${className}`}
    />
  );
}

/// A sheet over the window. One at a time, closed by the button or Escape.
export function Modal({
  title,
  subtitle,
  onClose,
  children,
  footer,
  width = "max-w-[460px]",
}: {
  title: string;
  subtitle?: React.ReactNode;
  onClose: () => void;
  children: React.ReactNode;
  footer?: React.ReactNode;
  width?: string;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="scrim-in fixed inset-0 z-40 flex items-center justify-center bg-black/35 p-6 backdrop-blur-[2px]" onMouseDown={onClose}>
      <div
        role="dialog"
        aria-label={title}
        onMouseDown={(e) => e.stopPropagation()}
        className={`rise flex max-h-full w-full ${width} flex-col overflow-hidden rounded-2xl bg-bg shadow-[var(--shadow)]`}
      >
        <div className="flex items-start justify-between gap-4 px-5 pb-1 pt-4">
          <div className="min-w-0">
            <h2 className="display text-[18px]">{title}</h2>
            {subtitle && <p className="mt-0.5 text-[12.5px] text-dim">{subtitle}</p>}
          </div>
          <IconButton onClick={onClose} title="Close" size="sm">
            <Icon.Close size={14} />
          </IconButton>
        </div>
        <div className="min-h-0 overflow-y-auto px-5 pb-5 pt-3">{children}</div>
        {footer && <div className="flex items-center justify-end gap-2 border-t border-line bg-panel/60 px-5 py-3">{footer}</div>}
      </div>
    </div>
  );
}

/// Something went wrong, in one line, until dismissed.
export function Notice({ text, onDismiss }: { text: string; onDismiss: () => void }) {
  return (
    <div className="fade-in flex items-start gap-2.5 border-b border-red/20 bg-red/8 px-4 py-2">
      <Icon.Warn size={14} className="mt-[3px] text-red" />
      <p className="selectable flex-1 text-[12.5px] leading-relaxed text-ink">{text}</p>
      <IconButton onClick={onDismiss} title="Dismiss" size="sm">
        <Icon.Close size={14} />
      </IconButton>
    </div>
  );
}

export function Empty({ title, children, art }: { title: string; children?: React.ReactNode; art?: React.ReactNode }) {
  return (
    <div className="flex h-full flex-col items-center justify-center px-8 text-center">
      {art && <div className="mb-5">{art}</div>}
      <p className="display text-[17px] text-ink">{title}</p>
      {children && <div className="mt-1.5 max-w-sm text-[13px] leading-relaxed text-dim">{children}</div>}
    </div>
  );
}

export function Code({ children }: { children: string }) {
  return (
    <code className="selectable block break-all rounded-lg border border-line bg-sunken/60 px-3 py-2 font-mono text-[11.5px] leading-relaxed text-ink">
      {children}
    </code>
  );
}

/// A small label beside a name: "exit", "auto", "this device".
export function Tag({ children, tone = "plain" }: { children: React.ReactNode; tone?: "plain" | "accent" | "amber" | "green" }) {
  const t = {
    plain: "border-line-2 text-dim",
    accent: "border-accent/40 bg-accent/8 text-accent",
    amber: "border-amber/40 bg-amber/8 text-amber",
    green: "border-green/40 bg-green/8 text-green",
  }[tone];
  return <span className={`caps inline-flex h-[18px] shrink-0 items-center rounded-[5px] border px-1.5 !text-[9.5px] ${t}`}>{children}</span>;
}

/// Tabs drawn as one pill with a sliding face.
export function Segmented<T extends string>({
  value,
  onChange,
  options,
  size = "md",
}: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: React.ReactNode; title?: string }[];
  size?: "sm" | "md";
}) {
  return (
    <div role="tablist" className={`inline-flex items-center rounded-[10px] bg-ink/6 p-[3px] ${size === "sm" ? "h-[28px]" : "h-[32px]"}`}>
      {options.map((o) => {
        const on = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            role="tab"
            aria-selected={on}
            title={o.title}
            onClick={() => onChange(o.value)}
            className={`flex h-full items-center gap-1.5 rounded-[7px] px-3 text-[12.5px] font-medium transition
              ${on ? "bg-tab text-ink shadow-[var(--shadow-sm)]" : "text-dim hover:text-ink"}`}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

/// A line of recent values: latency over the last minute or two.
export function Sparkline({ values, width = 120, height = 28, className = "" }: { values: number[]; width?: number; height?: number; className?: string }) {
  const pts = values.filter((v) => v > 0);
  if (pts.length < 2) {
    return <div className={`flex items-center text-[11px] text-dimmer ${className}`} style={{ width, height }}>gathering…</div>;
  }
  const max = Math.max(...pts) * 1.15;
  const min = Math.min(...pts) * 0.85;
  const span = Math.max(max - min, 1e-9);
  const step = width / (pts.length - 1);
  const xy = pts.map((v, i) => [i * step, height - 2 - ((v - min) / span) * (height - 4)] as const);
  const d = xy.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
  const last = xy[xy.length - 1];
  return (
    <svg width={width} height={height} className={`overflow-visible ${className}`} aria-hidden="true">
      <path d={`${d} L${width} ${height} L0 ${height} Z`} fill="currentColor" opacity="0.08" />
      <path d={d} fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={last[0]} cy={last[1]} r="2.5" fill="currentColor" />
    </svg>
  );
}

/// Seconds counting down to a moment, as m:ss.
export function useCountdown(until: number | null): string | null {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!until) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [until]);
  if (!until) return null;
  const s = Math.max(0, Math.round((until - now) / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}
