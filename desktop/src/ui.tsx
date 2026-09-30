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
  kbd,
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
  kbd?: string;
}) {
  const variants = {
    primary: "bg-primary text-primary-ink border-transparent hover:opacity-90 active:opacity-80",
    default: "bg-panel text-ink border-line-2 hover:bg-sunken active:bg-active shadow-[0_1px_1px_rgba(0,0,0,0.03)]",
    danger: "bg-panel text-ink border-line-2 hover:bg-sunken hover:border-dim active:bg-active",
    ghost: "bg-transparent text-dim border-transparent hover:bg-hover hover:text-ink active:bg-active",
  }[variant];
  const sizes = {
    sm: "h-7 px-2.5 text-[12.5px] gap-1.5 rounded-[7px]",
    md: "h-8 px-3 text-[13px] gap-1.5 rounded-lg",
    lg: "h-10 px-4 text-[14px] gap-2 rounded-[10px]",
  }[size];

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || busy}
      title={title}
      className={`inline-flex shrink-0 items-center justify-center border font-medium whitespace-nowrap transition-[background-color,opacity,color,border-color] duration-150
        disabled:cursor-not-allowed disabled:opacity-40 ${variants} ${sizes} ${className}`}
    >
      {busy ? <Spinner /> : icon}
      {children}
      {kbd && (
        <kbd className={`ml-0.5 font-sans text-[11px] font-normal ${variant === "primary" ? "opacity-55" : "text-dimmer"}`}>{kbd}</kbd>
      )}
    </button>
  );
}

export function IconButton({
  children,
  onClick,
  title,
  active,
  busy,
  disabled,
  size = "md",
}: {
  children: React.ReactNode;
  onClick?: () => void;
  title: string;
  active?: boolean;
  busy?: boolean;
  disabled?: boolean;
  size?: "sm" | "md";
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      aria-label={title}
      disabled={busy || disabled}
      className={`inline-flex shrink-0 items-center justify-center rounded-[7px] transition-colors duration-150
        hover:bg-hover active:bg-active disabled:opacity-40 ${size === "sm" ? "size-6" : "size-7"}
        ${active ? "bg-active text-ink" : "text-dim hover:text-ink"}`}
    >
      {busy ? <Spinner /> : children}
    </button>
  );
}

export function Spinner({ className = "" }: { className?: string }) {
  return (
    <svg className={`spin size-3.5 ${className}`} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.2" strokeWidth="2.5" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
    </svg>
  );
}

/// The switch. Ink when on: the one control in the window that changes the
/// machine's state, drawn in the same ink as every primary action.
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
  const knob = size === "lg" ? "size-[20px]" : "size-[16px]";
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
        ${on ? "bg-primary" : "bg-active"}
        ${disabled && !busy ? "opacity-40" : ""}`}
    >
      <span
        className={`absolute left-[2px] inline-flex items-center justify-center rounded-full shadow-[0_1px_2px_rgba(0,0,0,0.25),0_0_0_0.5px_rgba(0,0,0,0.06)] transition-[transform,background-color] duration-200 ease-[cubic-bezier(0.3,0.7,0.2,1)] ${knob}
          ${on ? `${travel} bg-primary-ink text-primary` : "translate-x-0 bg-white text-[#0c0c0e]"}`}
      >
        {busy && <Spinner className="size-2.5" />}
      </span>
    </button>
  );
}

export type Tone = "green" | "grey" | "amber" | "red";

/// A status mark, in ink only: solid for up, half for the long way round, a
/// ring for off, a cross for broken. It always sits beside a word that says
/// the same thing — the shape is a glance, the word is the answer.
export function Dot({ tone, size = "md" }: { tone: Tone; size?: "sm" | "md" }) {
  const px = size === "sm" ? 6 : 7;
  const box = { width: px, height: px };
  if (tone === "red") {
    return (
      <svg width={px + 2} height={px + 2} viewBox="0 0 10 10" className="shrink-0 text-ink" aria-hidden="true">
        <path d="M2 2l6 6M8 2l-6 6" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      </svg>
    );
  }
  if (tone === "amber") {
    return <span style={box} className="inline-block shrink-0 rounded-full border border-ink bg-[linear-gradient(90deg,var(--ink)_50%,transparent_50%)]" />;
  }
  if (tone === "grey") return <span style={box} className="inline-block shrink-0 rounded-full border-[1.5px] border-dimmer" />;
  return <span style={box} className="inline-block shrink-0 rounded-full bg-ink" />;
}

/// Three bars for how good a path is: all three direct and quick, fewer as it
/// gets slower, one through a relay, none offline. The words are always
/// beside them.
export function Signal({ latency, direct, online }: { latency: number; direct: boolean; online: boolean }) {
  const msv = latency / 1e6;
  const bars = !online ? 0 : !direct ? 1 : !latency || msv < 25 ? 3 : msv < 90 ? 2 : 1;
  return (
    <span className="inline-flex h-[11px] items-end gap-[2px]" aria-hidden="true">
      {[5, 8, 11].map((h, i) => (
        <span key={h} style={{ height: h }} className={`w-[3px] rounded-[1px] ${i < bars ? "bg-ink" : "bg-active"}`} />
      ))}
    </span>
  );
}

/// A small label beside a name.
export function Tag({ children, tone = "plain" }: { children: React.ReactNode; tone?: "plain" | "ink" }) {
  const t = tone === "ink" ? "bg-primary text-primary-ink" : "bg-active text-dim";
  return <span className={`inline-flex h-[18px] shrink-0 items-center rounded-[5px] px-1.5 text-[10.5px] font-medium ${t}`}>{children}</span>;
}

/// A shortcut as this platform spells it: ⌘K on a Mac, Ctrl+K everywhere
/// else. The keys are the same either way — the window answers to both.
export const shortcut = (mac: boolean, key: string) => (mac ? `⌘${key}` : `Ctrl+${key}`);

export function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="inline-flex h-[18px] min-w-[18px] items-center justify-center rounded-[5px] border border-line-2 bg-panel px-1 font-sans text-[10.5px] font-medium text-dim">
      {children}
    </kbd>
  );
}

/// A group of rows with a hairline round it.
export function Card({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <div className={`overflow-hidden rounded-xl border border-line bg-panel ${className}`}>{children}</div>;
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
      {icon && <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-sunken text-dim">{icon}</span>}
      <div className="min-w-0 flex-1">
        <div className={`truncate text-[13px] text-ink ${mono ? "font-mono text-[12.5px]" : ""}`}>{value}</div>
        {caption && <div className="mt-px text-[12px] leading-snug text-dim">{caption}</div>}
      </div>
      {right && <div className="flex shrink-0 items-center gap-1.5">{right}</div>}
    </>
  );
  const cls = "group/row flex min-h-[52px] items-center gap-3 border-b border-line px-4 py-2.5 last:border-0";
  if (onClick) {
    return (
      <button type="button" onClick={onClick} title={title} className={`${cls} w-full text-left transition-colors hover:bg-hover`}>
        {inner}
      </button>
    );
  }
  return <div className={cls}>{inner}</div>;
}

export function Section({
  title,
  hint,
  right,
  children,
}: {
  title: string;
  hint?: React.ReactNode;
  right?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section>
      <div className="mb-2 flex min-h-7 items-end justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-[12.5px] font-medium text-ink">{title}</h3>
          {hint && <p className="mt-0.5 text-[12px] leading-snug text-dim">{hint}</p>}
        </div>
        {right}
      </div>
      {children}
    </section>
  );
}

/// The strip across the top of a page: its name, one line under it, and the
/// page's own actions. The window is dragged by it.
export function PageHeader({
  title,
  sub,
  right,
  back,
}: {
  title: React.ReactNode;
  sub?: React.ReactNode;
  right?: React.ReactNode;
  back?: () => void;
}) {
  return (
    <header data-tauri-drag-region className="flex h-[60px] shrink-0 items-center gap-3 border-b border-line px-5">
      {back && (
        <IconButton title="Back" onClick={back}>
          <Icon.Back />
        </IconButton>
      )}
      <div className="flex min-w-0 flex-1 items-baseline gap-2.5" data-tauri-drag-region>
        <h1 className="truncate text-[15px] font-semibold tracking-[-0.01em]" data-tauri-drag-region>
          {title}
        </h1>
        {sub && (
          <span className="truncate text-[12.5px] text-dim" data-tauri-drag-region>
            {sub}
          </span>
        )}
      </div>
      {right && <div className="flex shrink-0 items-center gap-2">{right}</div>}
    </header>
  );
}

// --- toasts ---------------------------------------------------------------
// A word at the bottom of the window for a second and a half: "Copied".
// Copying is silent, and without it people click twice and wonder which one
// took. Module-level so anything can say something without threading a
// callback through every screen.

type ToastItem = { id: number; text: string; tone: "ok" | "error" };
const toastListeners = new Set<(t: ToastItem) => void>();
let toastId = 0;

export function toast(text: string, tone: "ok" | "error" = "ok") {
  const t = { id: ++toastId, text, tone };
  toastListeners.forEach((l) => l(t));
}

export function Toaster() {
  const [items, setItems] = useState<ToastItem[]>([]);
  useEffect(() => {
    const on = (t: ToastItem) => {
      setItems((xs) => [...xs.slice(-2), t]);
      setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== t.id)), t.tone === "error" ? 4000 : 1600);
    };
    toastListeners.add(on);
    return () => {
      toastListeners.delete(on);
    };
  }, []);
  return (
    <div className="pointer-events-none fixed inset-x-0 bottom-5 z-50 flex flex-col items-center gap-2" aria-live="polite">
      {items.map((t) => (
        <div
          key={t.id}
          className="rise-in flex max-w-[420px] items-center gap-2 rounded-full bg-primary py-1.5 pl-2.5 pr-3.5 text-[12.5px] font-medium text-primary-ink shadow-[var(--pop-shadow)]"
        >
          {t.tone === "ok" ? <Icon.Check size={14} className="opacity-70" /> : <Icon.Warn size={14} className="opacity-70" />}
          <span className="truncate">{t.text}</span>
        </div>
      ))}
    </div>
  );
}

/// Copy to the clipboard and say so for a moment.
export function useCopied(): [boolean, (text: string, what?: string) => void] {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1400);
    return () => clearTimeout(t);
  }, [copied]);

  return [
    copied,
    async (text: string, what?: string) => {
      await copyText(text);
      setCopied(true);
      toast(what ? `Copied ${what}` : "Copied");
    },
  ];
}

export function CopyButton({ value, label = "Copy", what }: { value: string; label?: string; what?: string }) {
  const [copied, copy] = useCopied();
  return (
    <IconButton onClick={() => copy(value, what ?? value)} title={copied ? "Copied" : label}>
      {copied ? <Icon.Check className="text-ink" /> : <Icon.Copy />}
    </IconButton>
  );
}

/// A value you click to copy: the whole thing is the button, with the copy
/// glyph arriving on hover — on the side away from the text's edge, so a
/// right-aligned value stays flush.
export function Copyable({
  value,
  display,
  what,
  mono = true,
  align = "start",
  className = "",
}: {
  value: string;
  display?: string;
  what?: string;
  mono?: boolean;
  align?: "start" | "end";
  className?: string;
}) {
  const [copied, copy] = useCopied();
  const glyph = copied ? (
    <Icon.Check size={13} className="shrink-0 text-ink" />
  ) : (
    <Icon.Copy size={13} className="shrink-0 text-dimmer opacity-0 transition-opacity group-hover/copy:opacity-100" />
  );
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        copy(value, what ?? value);
      }}
      title={`Copy ${what ?? value}`}
      className={`group/copy inline-flex max-w-full items-center gap-1.5 rounded-md py-0.5 text-left transition-colors hover:bg-hover
        ${align === "end" ? "-mr-1.5 pl-1 pr-1.5" : "-ml-1.5 pl-1.5 pr-1"} ${mono ? "font-mono text-[12px]" : ""} ${className}`}
    >
      {align === "end" && glyph}
      <span className="truncate">{display ?? value}</span>
      {align === "start" && glyph}
    </button>
  );
}

export function Search({
  value,
  onChange,
  placeholder = "Search",
  className = "",
  autoFocus,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  className?: string;
  autoFocus?: boolean;
}) {
  return (
    <label className={`relative block ${className}`}>
      <Icon.Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-dimmer" />
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => e.key === "Escape" && value && (e.stopPropagation(), onChange(""))}
        placeholder={placeholder}
        spellCheck={false}
        autoFocus={autoFocus}
        className="selectable h-8 w-full rounded-lg border border-line bg-sunken pl-8 pr-3 text-[13px] text-ink outline-none transition-colors placeholder:text-dimmer focus:border-line-2 focus:bg-panel"
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
      className={`selectable h-8 w-full rounded-lg border border-line-2 bg-panel px-3 text-[13px] text-ink outline-none transition-colors
        placeholder:text-dimmer focus:border-dim ${mono ? "font-mono text-[12.5px]" : ""} ${className}`}
    />
  );
}

/// A sheet over the window. One at a time, closed by the button, Escape, or
/// a click outside it.
export function Modal({
  title,
  sub,
  onClose,
  children,
  width = "max-w-[460px]",
  footer,
}: {
  title: string;
  sub?: React.ReactNode;
  onClose: () => void;
  children: React.ReactNode;
  width?: string;
  footer?: React.ReactNode;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="scrim-in fixed inset-0 z-40 flex items-center justify-center bg-black/25 p-6 backdrop-blur-[2px]" onMouseDown={onClose}>
      <div
        role="dialog"
        aria-label={title}
        onMouseDown={(e) => e.stopPropagation()}
        className={`pop-in flex max-h-full w-full flex-col ${width} overflow-hidden rounded-2xl bg-panel shadow-[var(--pop-shadow)]`}
      >
        <div className="flex items-start justify-between gap-4 px-5 pb-1 pt-4">
          <div className="min-w-0">
            <h2 className="text-[15px] font-semibold tracking-[-0.01em]">{title}</h2>
            {sub && <p className="mt-0.5 text-[12.5px] leading-relaxed text-dim">{sub}</p>}
          </div>
          <IconButton onClick={onClose} title="Close">
            <Icon.Close />
          </IconButton>
        </div>
        <div className="min-h-0 overflow-y-auto px-5 pb-5 pt-3">{children}</div>
        {footer && <div className="flex items-center justify-end gap-2 border-t border-line bg-sunken/60 px-5 py-3">{footer}</div>}
      </div>
    </div>
  );
}

/// Something went wrong, in a line across the top, until dismissed.
export function Notice({ text, onDismiss }: { text: string; onDismiss: () => void }) {
  return (
    <div className="fade-in flex items-start gap-2.5 border-b border-line bg-sunken px-5 py-2.5">
      <Icon.Warn size={15} className="mt-px text-ink" />
      <p className="selectable flex-1 text-[12.5px] leading-relaxed text-ink">{text}</p>
      <IconButton size="sm" onClick={onDismiss} title="Dismiss">
        <Icon.Close size={14} />
      </IconButton>
    </div>
  );
}

export function Empty({ title, icon, children }: { title: string; icon?: React.ReactNode; children?: React.ReactNode }) {
  return (
    <div className="flex h-full flex-col items-center justify-center px-8 text-center">
      {icon && <div className="mb-3 flex size-10 items-center justify-center rounded-xl border border-line bg-sunken text-dim">{icon}</div>}
      <p className="text-[14px] font-medium text-ink">{title}</p>
      {children && <div className="mt-1 max-w-[320px] text-[13px] leading-relaxed text-dim">{children}</div>}
    </div>
  );
}

export function Code({ children }: { children: string }) {
  return (
    <code className="selectable block break-all rounded-lg border border-line bg-sunken px-3 py-2 font-mono text-[11.5px] leading-relaxed text-ink-2">
      {children}
    </code>
  );
}
