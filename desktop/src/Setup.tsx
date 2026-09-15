import { useState } from "react";
import { looksLikeInvite, type Environment, type Tailscale } from "./api";
import type { Act } from "./App";
import { Button, Input, Notice } from "./ui";
import { Eye } from "./Eye";
import { Bones } from "./Bones";
import { TailscaleOffer } from "./Migrate";

/// The first screen, and the only one that asks a question.
///
/// Somebody who has never used a mesh does not know that a coordination plane
/// exists or that it has to live somewhere. The two cards turn that into the
/// one thing they already know: is this the first device, or is there one
/// already? Everything else — the server, the relay, the names, the tunnel —
/// follows from the answer.
///
/// Above them, her eye watches the pointer, and the name is spelled in bones,
/// as it is on the website.
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
  const [which, setWhich] = useState<"start" | "join" | null>(null);

  const cleaned = invite.trim().replace(/^makima\s+(join|up)\s+/i, "");
  const valid = looksLikeInvite(cleaned);

  async function start() {
    setWhich("start");
    await act({ kind: "up" });
    setWhich(null);
  }

  async function join() {
    if (!valid) return;
    setWhich("join");
    await act({ kind: "join", invite: cleaned });
    setWhich(null);
  }

  return (
    <div className="relative flex h-full flex-col overflow-hidden" data-tauri-drag-region>
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 bg-[radial-gradient(55%_45%_at_50%_18%,var(--glow),transparent_70%)]"
      />
      <div className={`h-[52px] shrink-0 ${mac ? "" : "hidden"}`} data-tauri-drag-region />
      {notice && <Notice text={notice} onDismiss={dismiss} />}

      <div className="relative flex flex-1 flex-col items-center justify-center px-8 pb-10" data-tauri-drag-region>
        <Eye follow blink glow className="w-[250px]" />
        <h1 className="mt-7">
          <span className="sr-only">makima</span>
          <Bones className="w-[210px]" />
        </h1>
        <p className="mt-4 font-display text-[21px] italic text-dim">Every machine you own, on one private network.</p>

        {!env.cli && (
          <p className="mt-6 max-w-md rounded-lg bg-red/8 px-4 py-2.5 text-center text-[13px] text-red">
            The makima command is missing from this app. Reinstall it, or install makima from the terminal first.
          </p>
        )}

        {tailscale && env.cli && (
          <div className="mt-7 flex w-full justify-center">
            <TailscaleOffer peers={tailscale.peers} onMove={onMigrate} />
          </div>
        )}

        <div className={`${tailscale && env.cli ? "mt-4" : "mt-8"} grid w-full max-w-[640px] grid-cols-2 gap-4`}>
          <Choice
            title="Start a network"
            body="This is the first device. It holds the network together, and every other device joins through it."
          >
            <Button variant="primary" size="lg" busy={busy && which === "start"} disabled={busy || !env.cli} onClick={start}>
              Start a network
            </Button>
          </Choice>

          <Choice
            title="Join a network"
            body="There is one already. Type the fifteen words the first device shows, or paste its invite."
          >
            <div className="flex w-full flex-col gap-2">
              <Input value={invite} onChange={setInvite} placeholder="fifteen words, or mk1_…" mono onEnter={join} autoFocus />
              <Button variant="primary" size="lg" busy={busy && which === "join"} disabled={busy || !valid || !env.cli} onClick={join}>
                Join
              </Button>
            </div>
          </Choice>
        </div>

        <p className="mt-7 max-w-md text-center text-[12px] leading-relaxed text-dimmer">
          You will be asked for your password once: makima creates a network interface, which needs it.
          {" "}From then on this device stays connected, after restarts too, until you disconnect.
          {" "}Get an invite on the first device with <span className="font-medium text-dim">Add device</span>.
        </p>
      </div>
    </div>
  );
}

function Choice({ title, body, children }: { title: string; body: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col rounded-2xl border border-line bg-card/80 p-5 backdrop-blur transition hover:border-accent/35">
      <h2 className="font-display text-[24px] leading-none tracking-tight">{title}</h2>
      <p className="mt-2 flex-1 text-[13px] leading-relaxed text-dim">{body}</p>
      <div className="mt-5 flex">{children}</div>
    </div>
  );
}
