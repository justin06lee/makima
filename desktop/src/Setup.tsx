import { useState } from "react";
import { looksLikeInvite, type Environment } from "./api";
import type { Act } from "./App";
import { Button, Input, Notice } from "./ui";
import { Icon } from "./icons";

/// The first screen, and the only one that asks a question.
///
/// Somebody who has never used a mesh does not know that a coordination plane
/// exists or that it has to live somewhere. The two cards turn that into the
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
}: {
  env: Environment;
  busy: boolean;
  act: Act;
  notice: string | null;
  dismiss: () => void;
  mac: boolean;
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
    <div className="flex h-full flex-col" data-tauri-drag-region>
      <div className={`h-[52px] shrink-0 ${mac ? "" : "hidden"}`} data-tauri-drag-region />
      {notice && <Notice text={notice} onDismiss={dismiss} />}

      <div className="flex flex-1 flex-col items-center justify-center px-8 pb-12" data-tauri-drag-region>
        <Icon.Mark size={40} className="text-ink" />
        <h1 className="mt-4 text-[24px] font-semibold tracking-tight">makima</h1>
        <p className="mt-1 text-[14px] text-dim">Every machine you own, on one private network.</p>

        {!env.cli && (
          <p className="mt-6 max-w-md rounded-lg bg-red/8 px-4 py-2.5 text-center text-[13px] text-red">
            The makima command is missing from this app. Reinstall it, or install makima from the terminal first.
          </p>
        )}

        <div className="mt-8 grid w-full max-w-[640px] grid-cols-2 gap-4">
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
              <Input
                value={invite}
                onChange={setInvite}
                placeholder="fifteen words, or mk1_…"
                mono
                onEnter={join}
                autoFocus
              />
              <Button variant="primary" size="lg" busy={busy && which === "join"} disabled={busy || !valid || !env.cli} onClick={join}>
                Join
              </Button>
            </div>
          </Choice>
        </div>

        <p className="mt-8 max-w-md text-center text-[12px] leading-relaxed text-dimmer">
          You will be asked for your password once: makima creates a network interface, which needs it.
          {" "}From then on this device stays connected, after restarts too, until you disconnect.
          {" "}Get an invite on the first device with <span className="font-mono">Add device</span>.
        </p>
      </div>
    </div>
  );
}

function Choice({ title, body, children }: { title: string; body: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col rounded-2xl border border-line bg-card p-5">
      <h2 className="text-[16px] font-semibold">{title}</h2>
      <p className="mt-1.5 flex-1 text-[13px] leading-relaxed text-dim">{body}</p>
      <div className="mt-5 flex">{children}</div>
    </div>
  );
}
