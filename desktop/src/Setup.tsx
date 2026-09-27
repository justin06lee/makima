import { useState } from "react";
import { looksLikeInvite, type Environment, type Tailscale } from "./api";
import type { Act } from "./App";
import { Button, Notice, Segmented } from "./ui";
import { Icon } from "./icons";
import { Iris } from "./Iris";
import { TailscaleOffer } from "./Migrate";

/// The first screen, and the only one that asks a question.
///
/// Somebody who has never used a mesh does not know that a coordination plane
/// exists or that it has to live somewhere. The choice turns that into the one
/// thing they already know: is this the first device, or is there one
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
  const [which, setWhich] = useState<"start" | "join">("start");
  const [invite, setInvite] = useState("");
  const [shake, setShake] = useState(0);

  const cleaned = invite.trim().replace(/^makima\s+(join|up)\s+/i, "");
  const valid = looksLikeInvite(cleaned);

  async function start() {
    await act({ kind: "up" });
  }

  async function join() {
    if (!valid) {
      setShake((n) => n + 1);
      return;
    }
    await act({ kind: "join", invite: cleaned });
  }

  return (
    <div className="flex h-full bg-bg">
      {/* The picture: the iris, and a few devices already on its rings. */}
      <div data-tauri-drag-region className="grain relative hidden w-[42%] shrink-0 flex-col justify-between overflow-hidden border-r border-line bg-panel px-9 pb-9 pt-[76px] md:flex">
        <div data-tauri-drag-region>
          <div className="caps text-dimmer">makima</div>
          <p className="display mt-2 max-w-[260px] text-[15px] leading-snug text-dim">A mesh network you own, end to end.</p>
        </div>

        <div className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2">
          <Orbit />
        </div>

        <ul className="relative space-y-2.5 text-[12.5px] text-dim">
          <Point icon={<Icon.Shield size={14} />}>No accounts, and no one else's servers.</Point>
          <Point icon={<Icon.Key size={14} />}>Keys are made here and never leave your machines.</Point>
          <Point icon={<Icon.Mesh size={14} />}>Devices talk directly wherever they can.</Point>
        </ul>
      </div>

      <div className="flex min-w-0 flex-1 flex-col">
        <div data-tauri-drag-region className={`h-[52px] shrink-0 ${mac ? "" : "hidden"}`} />
        {notice && <Notice text={notice} onDismiss={dismiss} />}

        <div data-tauri-drag-region className="flex min-h-0 flex-1 flex-col overflow-y-auto px-10 pb-8">
          <div className="mx-auto my-auto w-full max-w-[440px] py-4">
            <h1 className="display text-[30px] leading-[1.08]">
              Every machine you own,
              <br />
              on one private network.
            </h1>
            <p className="mt-3 text-[13.5px] leading-relaxed text-dim">Is this the first one, or is there a network already?</p>

            {!env.cli && (
              <p className="mt-5 rounded-lg bg-red/8 px-4 py-2.5 text-[12.5px] text-red">
                The makima command is missing from this app. Reinstall it, or install makima from the terminal first.
              </p>
            )}

            <div className="mt-6">
              <Segmented
                value={which}
                onChange={setWhich}
                options={[
                  { value: "start", label: "Start a network" },
                  { value: "join", label: "Join a network" },
                ]}
              />
            </div>

            <div className="mt-5 min-h-[188px]">
              {which === "start" ? (
                <div key="start" className="fade-in">
                  <ul className="space-y-2 text-[13px] text-dim">
                    <Point icon={<Num n={1} />}>This device holds the network — the others join through it.</Point>
                    <Point icon={<Num n={2} />}>Each new device joins with fifteen words shown here.</Point>
                    <Point icon={<Num n={3} />}>It stays connected, after restarts too, until you switch it off.</Point>
                  </ul>
                  <Button variant="primary" size="lg" busy={busy} disabled={busy || !env.cli} onClick={start} className="mt-6 w-full" icon={<Icon.Power size={16} />}>
                    Start a network
                  </Button>
                </div>
              ) : (
                <div key="join" className="fade-in">
                  <p className="text-[13px] leading-relaxed text-dim">
                    On the device that holds the network, choose <b className="font-medium text-ink">Add device</b>. Type the words it shows, or paste its invite.
                  </p>
                  <div key={shake} className={shake ? "shake" : ""}>
                    <textarea
                      value={invite}
                      onChange={(e) => setInvite(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          void join();
                        }
                      }}
                      placeholder="fifteen words, or mk1_…"
                      autoFocus
                      spellCheck={false}
                      autoCapitalize="off"
                      autoCorrect="off"
                      rows={2}
                      className="selectable mt-3 w-full resize-none rounded-xl border border-line-2 bg-raised px-3.5 py-2.5 font-mono text-[12.5px] leading-relaxed text-ink outline-none transition placeholder:text-dimmer focus:border-accent/60"
                    />
                  </div>
                  <Slots text={cleaned} valid={valid} />
                  <Button variant="primary" size="lg" busy={busy} disabled={busy || !env.cli || !cleaned} onClick={join} className="mt-4 w-full" icon={<Icon.ArrowRight size={16} />}>
                    Join
                  </Button>
                </div>
              )}
            </div>

            {tailscale && env.cli && (
              <div className="mt-5">
                <TailscaleOffer peers={tailscale.peers} onMove={onMigrate} />
              </div>
            )}

            <p className="mt-5 text-[11.5px] leading-relaxed text-dimmer">
              You'll be asked for your password once — makima makes a network interface, which needs it.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

/// The words typed so far, laid into their places, so it is plain how many
/// are left — and plain when an invite string has been pasted instead.
function Slots({ text, valid }: { text: string; valid: boolean }) {
  if (/^mk1_/.test(text)) {
    return (
      <p className={`mt-2 flex items-center gap-1.5 text-[12px] ${valid ? "text-green" : "text-dim"}`}>
        {valid ? <Icon.Check size={14} /> : <Icon.Info size={14} />}
        {valid ? "Invite recognised" : "That looks like the start of an invite"}
      </p>
    );
  }
  const words = text.split(/\s+/).filter(Boolean);
  // An invite can start with the server's address typed out, then ten words.
  const addressed = words.length > 0 && /[.:]/.test(words[0]);
  const total = addressed ? 11 : 15;
  return (
    <div className="mt-2">
      <div className="grid grid-cols-5 gap-1">
        {Array.from({ length: total }, (_, i) => {
          const w = words[i];
          return (
            <span
              key={i}
              className={`flex h-[22px] items-center justify-center truncate rounded-md px-1 font-mono text-[10.5px] transition
                ${w ? "bg-ink/8 text-ink" : "border border-dashed border-line-2 text-dimmer"}`}
            >
              {w ? (addressed && i === 0 ? "server" : w.slice(0, 7)) : i + 1}
            </span>
          );
        })}
      </div>
      <p className="mt-1.5 text-[11.5px] text-dimmer">
        {words.length === 0
          ? "The first four letters of each word are enough."
          : words.length < total
            ? `${words.length} of ${total} — ${total - words.length} to go`
            : valid
              ? "All there."
              : "That doesn't look like an invite yet."}
      </p>
    </div>
  );
}

function Point({ icon, children }: { icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <li className="flex items-start gap-2.5">
      <span className="mt-px flex size-[18px] shrink-0 items-center justify-center text-dimmer">{icon}</span>
      <span className="leading-relaxed">{children}</span>
    </li>
  );
}

function Num({ n }: { n: number }) {
  return <span className="flex size-[18px] items-center justify-center rounded-full bg-ink text-[10px] font-semibold text-bg">{n}</span>;
}

/// The iris with devices going round it — what the network will look like.
function Orbit() {
  return (
    <div className="relative size-[300px]">
      <svg viewBox="0 0 300 300" className="absolute inset-0" aria-hidden="true">
        <circle cx="150" cy="150" r="138" fill="none" stroke="var(--line-2)" strokeDasharray="1 6" strokeLinecap="round" />
        <circle cx="150" cy="150" r="104" fill="none" stroke="var(--line-2)" strokeDasharray="3 5" />
        <circle cx="150" cy="150" r="72" fill="none" stroke="var(--line-2)" />
      </svg>
      <div className="turn-slow absolute inset-0">
        <Sat x={150 + 72} y={150} tone="bg-green" />
        <Sat x={150 - 36} y={150 - 62} tone="bg-green" />
      </div>
      <div className="turn-mid absolute inset-0">
        <Sat x={150 - 74} y={150 + 73} tone="bg-amber" />
      </div>
      <div className="absolute inset-0 flex items-center justify-center">
        <Iris size={96} />
      </div>
    </div>
  );
}

function Sat({ x, y, tone }: { x: number; y: number; tone: string }) {
  return (
    <span className="absolute -translate-x-1/2 -translate-y-1/2" style={{ left: x, top: y }}>
      <span className={`block size-3 rounded-full ${tone} shadow-[0_0_0_3px_var(--panel)]`} />
    </span>
  );
}
