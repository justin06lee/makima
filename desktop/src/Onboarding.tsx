import { useEffect, useState } from "react";
import type { Tailscale } from "./api";
import { Button } from "./ui";
import { Icon } from "./icons";
import { TERMINAL, TerminalIcon, useTerminals } from "./Terminal";
import { Wave } from "./Wave";

/// Set once the first-open questions have been answered or skipped.
export const ONBOARDED = "makima:onboarded";

type Step = "terminal" | "tailscale";

/// The first time the app opens: two questions, each skipped when there is
/// nothing to ask. Which terminal SSH should open in — asked only when there
/// is more than one — and, when Tailscale is running here, whether to move
/// off it now. Saying no to the move is not a dead end: the sidebar and
/// Settings both still offer it.
export function Onboarding({ mac, tailscale, onDone }: { mac: boolean; tailscale: Tailscale | null; onDone: (move: boolean) => void }) {
  const terminals = useTerminals();
  const [chosen, setChosen] = useState<string | null>(() => localStorage.getItem(TERMINAL));
  const [at, setAt] = useState(0);

  const steps: Step[] = terminals === null ? [] : [...(terminals.length > 1 ? (["terminal"] as const) : []), ...(tailscale ? (["tailscale"] as const) : [])];

  useEffect(() => {
    if (terminals === null) return;
    // One terminal is not a question; remember it and move on.
    if (terminals.length === 1) localStorage.setItem(TERMINAL, terminals[0].id);
    if (terminals.length > 1 && !(chosen && terminals.some((t) => t.id === chosen))) setChosen(terminals[0].id);
    if (steps.length === 0) onDone(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [terminals]);

  if (terminals === null || steps.length === 0) {
    return <div className="h-full" data-tauri-drag-region />;
  }

  const step = steps[Math.min(at, steps.length - 1)];

  function next(pick = chosen) {
    if (step === "terminal" && pick) localStorage.setItem(TERMINAL, pick);
    if (at + 1 < steps.length) setAt(at + 1);
    else onDone(false);
  }

  return (
    <div className="flex h-full flex-col" data-tauri-drag-region>
      <div className={`${mac ? "h-[46px]" : "h-3"} shrink-0`} data-tauri-drag-region />

      <div className="flex min-h-0 flex-1 flex-col items-center overflow-y-auto px-8 pb-10" data-tauri-drag-region>
        <div className="my-auto w-full max-w-[420px]" data-tauri-drag-region>
          {steps.length > 1 && (
            <div className="mb-8 flex items-center justify-center gap-1.5" aria-label={`Step ${at + 1} of ${steps.length}`}>
              {steps.map((s, i) => (
                <span key={s} className={`h-1 rounded-full transition-all duration-300 ${i === at ? "w-5 bg-ink" : "w-1 bg-line-2"}`} />
              ))}
            </div>
          )}

          <div key={step} className="fade-in">
            {step === "terminal" && terminals && (
              <>
                <h1 className="text-center text-[24px] font-semibold tracking-[-0.03em]">What's your default terminal?</h1>
                <p className="mx-auto mt-2 max-w-[340px] text-center text-[13px] leading-relaxed text-dim">
                  SSH to your other devices opens here. You can change it any time in Settings.
                </p>

                <div role="radiogroup" aria-label="Terminal" className="mt-8 space-y-1">
                  {terminals.map((t) => {
                    const on = chosen === t.id;
                    return (
                      <button
                        key={t.id}
                        type="button"
                        role="radio"
                        aria-checked={on}
                        onClick={() => setChosen(t.id)}
                        onDoubleClick={() => {
                          setChosen(t.id);
                          next(t.id);
                        }}
                        className={`group flex h-[64px] w-full items-center gap-4 rounded-2xl pl-5 pr-3 text-left transition-[background-color,box-shadow] duration-200
                          ${on ? "bg-panel shadow-[var(--panel-shadow)]" : "hover:bg-hover"}`}
                      >
                        <span
                          className={`flex size-[18px] shrink-0 items-center justify-center rounded-full border transition-colors
                            ${on ? "border-ink bg-ink text-panel" : "border-line-2 group-hover:border-dim"}`}
                        >
                          {on && <Icon.Check size={11} />}
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-[15px] font-medium tracking-[-0.01em]">{t.name}</span>
                          {t.builtin && <span className="block text-[12px] text-dimmer">Comes with {mac ? "macOS" : "the system"}</span>}
                        </span>
                        <TerminalIcon id={t.id} size={44} />
                      </button>
                    );
                  })}
                </div>

                <Button className="mt-8 w-full" variant="primary" size="lg" onClick={() => next()} disabled={!chosen}>
                  Continue
                </Button>
              </>
            )}

            {step === "tailscale" && tailscale && (
              <>
                <h1 className="text-center text-[24px] font-semibold tracking-[-0.03em]">Coming from Tailscale?</h1>
                <p className="mx-auto mt-2 max-w-[360px] text-center text-[13px] leading-relaxed text-dim">
                  It's running here with {tailscale.peers} other device{tailscale.peers === 1 ? "" : "s"}
                  {tailscale.tailnet ? ` on ${tailscale.tailnet}` : ""}. makima can put itself on each of them, connect them all,
                  and take Tailscale off every one once makima works there.
                </p>

                <div className="my-10 flex items-center gap-4 px-2">
                  <span className="text-[13px] font-medium text-dim">Tailscale</span>
                  <Wave className="min-w-0 flex-1 text-ink" height={28} pulse={54} period={2600} />
                  <span className="text-[13px] font-semibold tracking-[-0.02em]">makima</span>
                </div>

                <Button className="w-full" variant="primary" size="lg" onClick={() => onDone(true)}>
                  Move my devices
                </Button>
                <Button className="mt-2 w-full" variant="ghost" size="lg" onClick={() => onDone(false)}>
                  Skip for now
                </Button>
                <p className="mt-3 text-center text-[11.5px] text-dimmer">Nothing changes until you choose what moves. You can start it later from the sidebar or Settings.</p>
              </>
            )}

            {at > 0 && (
              <div className="mt-6 text-center">
                <button type="button" onClick={() => setAt(at - 1)} className="inline-flex items-center gap-1 text-[12px] text-dim hover:text-ink">
                  <Icon.Back size={13} /> Back
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
