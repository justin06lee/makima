import { useRef, useState } from "react";
import { looksLikeInvite, type Environment, type Tailscale } from "./api";
import type { Act } from "./App";
import { Button, Notice } from "./ui";
import { Icon } from "./icons";

/// The first screen, and the only one that asks a question.
///
/// Somebody who has never used a mesh does not know that a coordination plane
/// exists or that it has to live somewhere. The two choices turn that into the
/// one thing they already know: is this the first device, or is there one
/// already? Everything else — the server, the relay, the names, the tunnel —
/// follows from the answer.
export function Setup({
  env,
  busy,
  act,
  notice,
  dismiss,
  mac,
  tailscale,
  onMigrate,
}: {
  env: Environment;
  busy: boolean;
  act: Act;
  notice: string | null;
  dismiss: () => void;
  mac: boolean;
  tailscale: Tailscale | null;
  onMigrate: () => void;
}) {
  const [invite, setInvite] = useState("");
  const [which, setWhich] = useState<"start" | "join">("start");
  const [working, setWorking] = useState(false);

  const cleaned = invite.trim().replace(/^makima\s+(join|up)\s+/i, "");
  const valid = looksLikeInvite(cleaned);

  async function start() {
    setWorking(true);
    await act({ kind: "up" });
    setWorking(false);
  }

  async function join() {
    if (!valid) return;
    setWorking(true);
    await act({ kind: "join", invite: cleaned });
    setWorking(false);
  }

  return (
    <div className="flex h-full flex-col" data-tauri-drag-region>
      <div className={`${mac ? "h-[46px]" : "h-3"} shrink-0`} data-tauri-drag-region />
      {notice && <Notice text={notice} onDismiss={dismiss} />}

      <div className="flex min-h-0 flex-1 flex-col items-center overflow-y-auto px-8 pb-10" data-tauri-drag-region>
        <div className="my-auto w-full max-w-[440px] pt-4" data-tauri-drag-region>
          <div className="fade-in text-center" data-tauri-drag-region>
            <h1 className="text-[28px] font-semibold tracking-[-0.035em]">makima</h1>
            <p className="mt-1 text-[13.5px] text-dim">Every machine you own, on one private network.</p>
          </div>

          {!env.cli && (
            <p className="mt-6 rounded-xl border border-red/20 bg-red/[0.06] px-4 py-3 text-center text-[12.5px] leading-relaxed text-red">
              The makima command is missing from this app. Reinstall it, or install makima from the terminal first.
            </p>
          )}

          <div className="fade-in mt-8 overflow-hidden rounded-2xl border border-line bg-panel shadow-[var(--panel-shadow)]" style={{ animationDelay: "60ms" }}>
            <Option
              on={which === "start"}
              onPick={() => setWhich("start")}
              icon={<Icon.Plus size={16} />}
              title="Start a network"
              body="This is your first device. The others join through it."
            >
              <p className="text-[12.5px] leading-relaxed text-dim">
                makima makes a private network here and keeps it running whenever this device is on. Then add your other devices with the fifteen words it shows you.
              </p>
              <Button className="mt-4 w-full" variant="primary" size="lg" busy={working && which === "start"} disabled={busy || !env.cli} onClick={start}>
                Start a network
              </Button>
            </Option>

            <Option
              on={which === "join"}
              onPick={() => setWhich("join")}
              icon={<Icon.Link size={16} />}
              title="Join a network"
              body="Another device already has one."
            >
              <WordsInput value={invite} onChange={setInvite} onEnter={join} />
              <Button className="mt-4 w-full" variant="primary" size="lg" busy={working && which === "join"} disabled={busy || !valid || !env.cli} onClick={join}>
                Join
              </Button>
              <p className="mt-2.5 text-center text-[11.5px] text-dimmer">
                Get the words from <span className="text-dim">Add device</span> on a device that's already connected.
              </p>
            </Option>
          </div>

          <p className="mt-5 text-center text-[11.5px] leading-relaxed text-dimmer">
            You'll be asked for your password once — makima creates a network interface. From then on this device stays connected, after restarts too, until you turn it off.
          </p>

          {tailscale && env.cli && (
            <button
              type="button"
              onClick={onMigrate}
              className="fade-in group mt-6 flex w-full items-center gap-3 rounded-xl border border-line bg-panel/60 px-4 py-3 text-left transition-colors hover:border-line-2 hover:bg-panel"
            >
              <div className="min-w-0 flex-1">
                <div className="text-[12.5px] font-medium">Coming from Tailscale?</div>
                <div className="mt-px text-[12px] text-dim">
                  It's running here with {tailscale.peers} other device{tailscale.peers === 1 ? "" : "s"}. Move them all to makima in one go.
                </div>
              </div>
              <Icon.Arrow size={15} className="text-dim transition-transform group-hover:translate-x-0.5 group-hover:text-ink" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function Option({
  on,
  onPick,
  icon,
  title,
  body,
  children,
}: {
  on: boolean;
  onPick: () => void;
  icon: React.ReactNode;
  title: string;
  body: string;
  children: React.ReactNode;
}) {
  return (
    <div className="border-b border-line last:border-0">
      <button type="button" role="radio" aria-checked={on} onClick={onPick} className={`flex w-full items-center gap-3.5 px-5 py-4 text-left transition-colors ${on ? "" : "hover:bg-hover"}`}>
        <span className={`flex size-9 shrink-0 items-center justify-center rounded-[10px] transition-colors ${on ? "bg-primary text-primary-ink" : "bg-sunken text-dim"}`}>{icon}</span>
        <span className="min-w-0 flex-1">
          <span className="block text-[14px] font-medium">{title}</span>
          <span className="block text-[12.5px] text-dim">{body}</span>
        </span>
        <span className={`flex size-[18px] shrink-0 items-center justify-center rounded-full border transition-colors ${on ? "border-primary bg-primary" : "border-line-2"}`}>
          {on && <span className="size-1.5 rounded-full bg-primary-ink" />}
        </span>
      </button>
      {on && <div className="fade-in px-5 pb-5">{children}</div>}
    </div>
  );
}

/// Where the fifteen words are typed: fifteen numbered slots that are the
/// input themselves. A space moves to the next one, Backspace in an empty one
/// goes back, and pasting all fifteen at once — or an mk1_ invite — drops them
/// into place. So it is plain how many are left, and a skipped word shows.
function WordsInput({ value, onChange, onEnter }: { value: string; onChange: (v: string) => void; onEnter: () => void }) {
  const refs = useRef<(HTMLInputElement | null)[]>([]);
  const cleaned = value.trim().replace(/^makima\s+(join|up)\s+/i, "");
  const pasted = /^mk1_/.test(cleaned) ? cleaned : null;
  const [slots, setSlots] = useState<string[]>(() => (pasted ? [] : cleaned.split(/\s+/).filter(Boolean)));
  const count = Math.max(15, slots.length);
  const filled = slots.filter(Boolean).length;
  const ok = looksLikeInvite(cleaned);

  function commit(next: string[]) {
    setSlots(next);
    onChange(next.filter(Boolean).join(" "));
  }

  function type(i: number, raw: string) {
    const text = raw.replace(/^makima\s+(join|up)\s+/i, "");
    // A pasted invite, not the first letters of a word being typed.
    if (/^\s*mk1_\S{8,}/.test(text)) {
      onChange(text.trim());
      return;
    }
    const parts = text.split(/\s+/);
    const next = [...slots];
    while (next.length < i) next.push("");
    if (parts.length === 1) {
      next[i] = parts[0].toLowerCase();
      commit(next);
      return;
    }
    // A space, or several words pasted at once: spread them from here on.
    const words = parts.filter(Boolean).map((w) => w.toLowerCase());
    words.forEach((w, k) => (next[i + k] = w));
    commit(next);
    // Now, not on the next frame: a fast typist's next key is already on its
    // way, and it belongs in the next slot.
    refs.current[Math.min(i + Math.max(words.length, 1), count - 1)]?.focus();
  }

  function key(i: number, e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") {
      e.preventDefault();
      onEnter();
    } else if (e.key === "Backspace" && !slots[i] && i > 0) {
      e.preventDefault();
      refs.current[i - 1]?.focus();
    } else if (e.key === "ArrowRight" && e.currentTarget.selectionStart === e.currentTarget.value.length && i < count - 1) {
      refs.current[i + 1]?.focus();
    } else if (e.key === "ArrowLeft" && e.currentTarget.selectionStart === 0 && i > 0) {
      refs.current[i - 1]?.focus();
    }
  }

  if (pasted) {
    return (
      <div className="flex items-center gap-3 rounded-[10px] border border-line bg-sunken px-3 py-2.5">
        <span className={`flex size-6 shrink-0 items-center justify-center rounded-full ${ok ? "bg-green/15 text-green" : "bg-active text-dim"}`}>
          {ok ? <Icon.Check size={13} /> : <Icon.Warn size={13} />}
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-[12.5px] font-medium">{ok ? "Invite recognised" : "That invite looks cut short"}</div>
          <div className="truncate font-mono text-[11px] text-dimmer">{pasted}</div>
        </div>
        <button type="button" onClick={() => onChange("")} className="text-[12px] text-dim hover:text-ink">
          Clear
        </button>
      </div>
    );
  }

  return (
    <div>
      <ol className="grid grid-cols-3 gap-1.5">
        {Array.from({ length: count }, (_, i) => (
          <li key={i} className="relative">
            <span className="tabular pointer-events-none absolute left-2 top-1/2 w-4 -translate-y-1/2 text-right text-[10px] text-dimmer">{i + 1}</span>
            <input
              ref={(el) => {
                refs.current[i] = el;
              }}
              value={slots[i] ?? ""}
              onChange={(e) => type(i, e.target.value)}
              onKeyDown={(e) => key(i, e)}
              autoFocus={i === 0}
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              aria-label={`Word ${i + 1}`}
              className={`selectable h-[30px] w-full rounded-md border pl-7 pr-2 font-mono text-[12px] text-ink outline-none transition-colors focus:border-dim focus:bg-panel focus-visible:!shadow-none
                ${slots[i] ? "border-line bg-sunken" : "border-dashed border-line-2 bg-transparent"}`}
            />
          </li>
        ))}
      </ol>
      <div className="mt-2 flex items-center justify-between text-[11.5px]">
        <span className="text-dimmer">Or paste the whole invite into any slot.</span>
        <span className="tabular">{ok ? <span className="text-green">Ready</span> : <span className="text-dimmer">{filled} of 15</span>}</span>
      </div>
    </div>
  );
}
