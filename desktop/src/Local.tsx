import { useState } from "react";
import { api, type Status } from "./api";
import { Button, Copyable, Dot, Panel } from "./ui";

/// This machine's own published ports.
///
/// The list is mostly things makima found by itself — auto-serve publishes
/// loopback services as they appear — so the useful action is taking one *off*
/// the mesh, not putting one on.
export function Published({
  status,
  onAllow,
  onDeny,
  busy,
}: {
  status: Status;
  onAllow: (port: number) => void;
  onDeny: (port: number) => void;
  busy: boolean;
}) {
  const [port, setPort] = useState("");
  const services = status.services ?? [];

  function add() {
    const n = Number(port);
    if (!Number.isInteger(n) || n < 1 || n > 65535) return;
    onAllow(n);
    setPort("");
  }

  return (
    <Panel
      title="Published from this machine"
      right={
        <div className="flex items-center gap-1.5">
          <input
            value={port}
            onChange={(e) => setPort(e.target.value.replace(/\D/g, "").slice(0, 5))}
            onKeyDown={(e) => e.key === "Enter" && add()}
            placeholder="port"
            inputMode="numeric"
            className="selectable w-16 rounded border border-line-2 bg-panel-2 px-2 py-1
              font-mono text-[12px] text-ink outline-none placeholder:text-dimmer
              focus:border-gold/50"
          />
          <Button onClick={add} busy={busy} disabled={!port}>
            publish
          </Button>
        </div>
      }
    >
      {services.length === 0 ? (
        <p className="px-4 py-6 text-center text-[13px] text-dim">
          Nothing published yet. Anything listening on 127.0.0.1 appears here on its own.
        </p>
      ) : (
        <ul>
          {services.map((s) => (
            <li
              key={s.port}
              className="flex items-center justify-between gap-3 border-b border-line/60 px-4 py-2 last:border-0"
            >
              <div className="flex min-w-0 items-center gap-2">
                <Dot tone={!s.listening ? "crimson" : s.target_up ? "green" : "gold"} />
                <span className="truncate font-mono text-[12px]">
                  {s.name ? `${s.name} ` : ""}
                  <span className="text-dim">:{s.port}</span>
                </span>
                <span className="truncate font-mono text-[11px] text-dimmer">→ {s.target}</span>
                {s.auto && (
                  <span className="shrink-0 text-[10px] uppercase tracking-wide text-dimmer">auto</span>
                )}
                {!s.target_up && s.listening && (
                  <span className="shrink-0 text-[11px] text-gold">nothing behind it</span>
                )}
              </div>
              <Button tone="quiet" busy={busy} onClick={() => onDeny(s.port)} title="Stop publishing">
                remove
              </Button>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

/// Adding a machine — an invite for a mesh with a control plane, a pairing
/// address for one without. The app never has to explain which; it asks the
/// daemon what kind of mesh this is and offers the right one.
export function AddMachine({ status, busy, run }: {
  status: Status;
  busy: boolean;
  run: (kind: "invite" | "pair") => Promise<string | null>;
}) {
  const [token, setToken] = useState<string | null>(null);
  const serverless = status.serverless;
  const verb = serverless ? "pair" : "invite";

  const existing = status.pairing?.address ?? null;
  const shown = token ?? existing;

  return (
    <Panel title="Add a machine">
      <div className="px-4 py-3">
        {shown ? (
          <>
            <p className="text-[12px] text-dim">
              Run this on the other machine{serverless ? "" : " to join"}:
            </p>
            <div className="selectable mt-2 max-h-24 overflow-y-auto rounded border border-line-2 bg-panel-2 p-2.5">
              <code className="block break-all font-mono text-[11px] leading-relaxed text-gold">
                makima {serverless ? "pair" : "join"} {shown}
              </code>
            </div>
            <div className="mt-2 flex items-center gap-2">
              <Copyable
                value={`makima ${serverless ? "pair" : "join"} ${shown}`}
                className="text-[12px] text-dim"
              />
              <span className="ml-auto text-[11px] text-dimmer">
                {status.pairing
                  ? `open until ${new Date(status.pairing.expires).toLocaleTimeString()}`
                  : "expires in an hour"}
              </span>
            </div>
          </>
        ) : (
          <div className="flex items-center justify-between gap-3">
            <p className="text-[13px] text-dim">
              {serverless
                ? "Publish an address for one machine to pair with."
                : "Mint a one-time invite for the next machine."}
            </p>
            <Button
              tone="gold"
              busy={busy}
              onClick={async () => setToken(await run(verb))}
            >
              {serverless ? "Pair a machine" : "Create invite"}
            </Button>
          </div>
        )}
      </div>
    </Panel>
  );
}

/// The doctor's checks, on demand.
///
/// Not shown until asked for: a permanent list of green ticks is noise, and
/// the one time it matters is the time something is wrong.
export function Diagnostics() {
  const [checks, setChecks] = useState<
    { name: string; ok: boolean; detail: string; fix?: string; warning?: boolean }[] | null
  >(null);
  const [running, setRunning] = useState(false);

  async function run() {
    setRunning(true);
    try {
      setChecks((await api.doctor()).checks);
    } catch (e) {
      setChecks([{ name: "Diagnostics", ok: false, detail: String(e) }]);
    } finally {
      setRunning(false);
    }
  }

  const bad = checks?.filter((c) => !c.ok) ?? [];

  return (
    <Panel
      title="Diagnosis"
      right={
        <Button onClick={run} busy={running}>
          {checks ? "check again" : "run checks"}
        </Button>
      }
    >
      {!checks ? (
        <p className="px-4 py-4 text-[13px] text-dim">
          The long-form answer to “why is this not working”.
        </p>
      ) : bad.length === 0 ? (
        <p className="flex items-center gap-2 px-4 py-4 text-[13px] text-dim">
          <Dot tone="green" />
          All {checks.length} checks passed.
        </p>
      ) : (
        <ul>
          {bad.map((c) => (
            <li key={c.name} className="border-b border-line/60 px-4 py-2.5 last:border-0">
              <div className="flex items-center gap-2">
                <Dot tone={c.warning ? "gold" : "crimson"} />
                <span className="text-[13px] font-medium">{c.name}</span>
              </div>
              <p className="mt-0.5 pl-4 text-[12px] text-dim">{c.detail}</p>
              {c.fix && (
                <code className="selectable mt-1 block pl-4 font-mono text-[11px] text-gold">
                  {c.fix}
                </code>
              )}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
