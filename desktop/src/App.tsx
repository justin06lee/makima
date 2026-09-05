import { useCallback, useEffect, useState } from "react";
import { api, type Action, type Snapshot, type Status } from "./api";
import { Button, Copyable, Dot } from "./ui";
import { Peers } from "./Peers";
import { AddMachine, Diagnostics, Published } from "./Local";

/// How often the window refreshes while it is open.
///
/// Two seconds. Paths change on their own — a relayed peer upgrades to direct
/// without anybody asking — and a window showing a stale path is worse than
/// one that flickers, because the whole reason to look is to find out what is
/// happening now.
const POLL = 2000;

export default function App() {
  const [snap, setSnap] = useState<Snapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setSnap(await api.status());
    } catch (e) {
      setSnap({ running: false, error: String(e) });
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, POLL);
    return () => clearInterval(t);
  }, [refresh]);

  useEffect(() => {
    if (!note) return;
    const t = setTimeout(() => setNote(null), 5000);
    return () => clearTimeout(t);
  }, [note]);

  /// Run a privileged action and fold the result back into the view.
  const act = useCallback(
    async (action: Action): Promise<string | null> => {
      setBusy(true);
      setNote(null);
      try {
        const out = await api.act(action);
        if (!out.ok) {
          // "cancelled" is the user saying no at the auth prompt. That is an
          // answer, not a failure, and it should not look like one.
          if (out.output !== "cancelled") setNote(out.output);
          return null;
        }
        await refresh();
        return out.output || null;
      } catch (e) {
        setNote(String(e));
        return null;
      } finally {
        setBusy(false);
      }
    },
    [refresh],
  );

  if (!snap) return <Splash />;
  if (!snap.running || !snap.status) return <Offline snap={snap} busy={busy} act={act} />;

  return (
    <Connected status={snap.status} busy={busy} act={act} note={note} dismiss={() => setNote(null)} />
  );
}

function Splash() {
  return (
    <main className="flex h-full items-center justify-center" data-tauri-drag-region>
      <p className="pulse text-[13px] text-dimmer">looking for makimad…</p>
    </main>
  );
}

/// Nothing is running. This is the most common state a desktop app finds, and
/// it is not an error — it is the thing the button exists to fix.
function Offline({
  snap,
  busy,
  act,
}: {
  snap: Snapshot;
  busy: boolean;
  act: (a: Action) => Promise<string | null>;
}) {
  const permission = snap.error?.includes("not readable");

  return (
    <main className="flex h-full flex-col items-center justify-center gap-5 px-10 text-center" data-tauri-drag-region>
      <div className="flex items-center gap-2.5">
        <Dot tone="off" />
        <h1 className="text-[15px] font-medium">makima is not running</h1>
      </div>

      <p className="max-w-sm text-[13px] leading-relaxed text-dim">
        {permission
          ? "The daemon is running, but its socket belongs to a different account — makimad gives it to whoever ran makima up."
          : "Bring the tunnel up and this machine joins its mesh. If there is no mesh yet, this machine makes one."}
      </p>

      {!permission && (
        <Button tone="gold" busy={busy} onClick={() => act({ kind: "up" })}>
          Connect
        </Button>
      )}

      {snap.error && !permission && (
        <p className="selectable max-w-md font-mono text-[11px] text-dimmer">{snap.error}</p>
      )}
    </main>
  );
}

function Connected({
  status,
  busy,
  act,
  note,
  dismiss,
}: {
  status: Status;
  busy: boolean;
  act: (a: Action) => Promise<string | null>;
  note: string | null;
  dismiss: () => void;
}) {
  return (
    <main className="flex h-full flex-col overflow-hidden">
      <Header status={status} busy={busy} act={act} />

      {note && (
        <div className="flex items-start gap-2 border-b border-crimson/30 bg-crimson/10 px-5 py-2.5">
          <Dot tone="crimson" />
          <p className="selectable flex-1 font-mono text-[11px] leading-relaxed text-ink">{note}</p>
          <button onClick={dismiss} className="text-[11px] text-dim hover:text-ink">
            dismiss
          </button>
        </div>
      )}

      <div className="flex-1 space-y-3 overflow-y-auto px-5 py-4">
        <Peers status={status} busy={busy} onExitNode={(name) => act({ kind: "exit-node", name })} />
        <AddMachine
          status={status}
          busy={busy}
          run={(kind) => act({ kind } as Action)}
        />
        <Published
          status={status}
          busy={busy}
          onAllow={(port) => act({ kind: "allow", port })}
          onDeny={(port) => act({ kind: "deny", port })}
        />
        <Diagnostics />
      </div>
    </main>
  );
}

function Header({
  status,
  busy,
  act,
}: {
  status: Status;
  busy: boolean;
  act: (a: Action) => Promise<string | null>;
}) {
  const mode = status.managed ? "control plane" : status.serverless ? "paired" : "static";

  return (
    // pt-7 clears the traffic lights, which float over the content with an
    // overlay title bar rather than sitting in a strip of their own.
    <header className="border-b border-line bg-panel px-5 pb-3.5 pt-7" data-tauri-drag-region>
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Dot tone="green" />
            <h1 className="truncate text-[15px] font-medium">{status.node.name}</h1>
            <span className="rounded border border-line-2 px-1.5 py-px text-[10px] uppercase tracking-wide text-dimmer">
              {mode}
            </span>
          </div>

          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-dim">
            <Copyable value={status.node.address} className="text-dim" />
            {status.relay.url && (
              <span className="flex items-center gap-1.5">
                <Dot tone={status.relay.connected ? "green" : "crimson"} />
                relay {status.relay.connected ? "up" : "down"}
              </span>
            )}
            {status.domain && <span className="text-dimmer">*.{status.domain}</span>}
            {status.exit_node && <span className="text-gold">via {status.exit_node}</span>}
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-1.5">
          {status.ssh.active && (
            <span
              title={`ssh as ${status.ssh.user} — ${status.ssh.fingerprint}`}
              className="rounded border border-line-2 px-1.5 py-1 text-[10px] uppercase tracking-wide text-dimmer"
            >
              ssh
            </span>
          )}
          {status.inbox.active && (
            <span
              title={`files from peers land in ${status.inbox.dir}`}
              className="rounded border border-line-2 px-1.5 py-1 text-[10px] uppercase tracking-wide text-dimmer"
            >
              inbox{status.inbox.received > 0 ? ` ${status.inbox.received}` : ""}
            </span>
          )}
          <Button tone="crimson" busy={busy} onClick={() => act({ kind: "down" })} title="Stop, and put this machine back">
            Disconnect
          </Button>
        </div>
      </div>
    </header>
  );
}
