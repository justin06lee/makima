import { useState } from "react";
import { api, ms, type Peer, type Ping, type Status } from "./api";
import { Button, Copyable, Dot, Panel } from "./ui";

/// One machine, its path, and what it publishes.
///
/// The path is the thing worth surfacing: a relayed tunnel and a direct one
/// look identical from the outside except for an order of magnitude of
/// latency, and that difference was previously only visible in a terminal.
function PeerRow({
  peer,
  exitNode,
  onExitNode,
  busy,
}: {
  peer: Peer;
  exitNode?: string;
  onExitNode: (name: string) => void;
  busy: boolean;
}) {
  const [ping, setPing] = useState<Ping | null>(null);
  const [pinging, setPinging] = useState(false);

  const isExit = exitNode === peer.name;
  const path = ping ?? peer;
  const latency = ping ? (ping.direct ? ping.latency : ping.relay_latency) : peer.latency;

  async function probe() {
    setPinging(true);
    try {
      setPing(await api.ping(peer.name));
    } catch {
      // A failed probe is not worth an error banner: the row already says
      // what it knows, and the next poll will correct it.
    } finally {
      setPinging(false);
    }
  }

  return (
    <div className="border-b border-line/60 px-4 py-3 last:border-0">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Dot tone={peer.online ? "green" : "off"} />
            <span className="truncate text-[14px] font-medium">{peer.name}</span>
            {isExit && (
              <span className="rounded border border-gold/40 bg-gold/10 px-1.5 py-px text-[10px] uppercase tracking-wide text-gold">
                exit
              </span>
            )}
          </div>

          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-dim">
            <Copyable value={peer.address} className="text-dim" />
            <span className="flex items-center gap-1.5">
              <Dot tone={path.direct ? "green" : peer.relay_url ? "gold" : "off"} />
              {path.direct ? "direct" : peer.relay_url ? "via relay" : "no path"}
              {latency ? <span className="text-dimmer">{ms(latency)}</span> : null}
            </span>
          </div>

          {peer.services && peer.services.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {peer.services.map((s) => (
                <ServiceChip key={s.port} host={peer.address} port={s.port} name={s.name} scheme={s.scheme} />
              ))}
            </div>
          )}
        </div>

        <div className="flex shrink-0 items-center gap-1.5">
          <Button onClick={probe} busy={pinging} title="Probe the path to this machine">
            ping
          </Button>
          {peer.exit_node && (
            <Button
              tone={isExit ? "crimson" : "quiet"}
              busy={busy}
              onClick={() => onExitNode(isExit ? "" : peer.name)}
              title={isExit ? "Stop routing through this machine" : "Route this machine's traffic here"}
            >
              {isExit ? "stop" : "use as exit"}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

/// A published port. Clickable when it is something a browser can open.
function ServiceChip({
  host,
  port,
  name,
  scheme,
}: {
  host: string;
  port: number;
  name?: string;
  scheme?: string;
}) {
  const label = name ? `${name}:${port}` : String(port);

  if (!scheme) {
    return (
      <span className="rounded border border-line-2 bg-panel-2 px-1.5 py-0.5 font-mono text-[11px] text-dimmer">
        {label}
      </span>
    );
  }

  return (
    <button
      onClick={async () => {
        const { openUrl } = await import("@tauri-apps/plugin-opener");
        await openUrl(`${scheme}://${host}:${port}`);
      }}
      title={`Open ${scheme}://${host}:${port}`}
      className="rounded border border-gold/30 bg-gold/10 px-1.5 py-0.5 font-mono text-[11px] text-gold transition hover:bg-gold/20"
    >
      {label} ↗
    </button>
  );
}

export function Peers({
  status,
  onExitNode,
  busy,
}: {
  status: Status;
  onExitNode: (name: string) => void;
  busy: boolean;
}) {
  if (status.peers.length === 0) {
    return (
      <Panel title="Machines">
        <div className="px-4 py-8 text-center text-[13px] text-dim">
          <p>No other machines yet.</p>
          <p className="mt-1 text-dimmer">
            {status.serverless
              ? "Pair one from the header above."
              : "Use Invite to add one."}
          </p>
        </div>
      </Panel>
    );
  }

  const online = status.peers.filter((p) => p.online).length;

  return (
    <Panel
      title="Machines"
      right={
        <span className="text-[11px] text-dimmer">
          {online} of {status.peers.length} reachable
        </span>
      }
    >
      {status.peers.map((p) => (
        <PeerRow
          key={p.address || p.name}
          peer={p}
          exitNode={status.exit_node}
          onExitNode={onExitNode}
          busy={busy}
        />
      ))}
    </Panel>
  );
}
