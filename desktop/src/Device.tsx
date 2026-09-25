import { useState } from "react";
import { api, fqdn, inTauri, ms, openExternal, openFolder, type Environment, type Peer, type Ping, type Status } from "./api";
import type { Act, History, Page } from "./App";
import { Button, Card, CopyButton, Copyable, Dot, IconButton, Row, Section, Sparkline, Spinner, Tag, Toggle } from "./ui";
import { Icon } from "./icons";
import { Iris } from "./Iris";
import { useCopy } from "./toast";

/// A file on its way to a device, or recently arrived.
export type Send = { id: number; peer: string; file: string; state: "sending" | "ok" | "failed"; note?: string };

/// How a peer is reached, in the words and the colour the map uses.
export function reach(p: Peer, exit?: boolean): { tone: "green" | "amber" | "grey" | "accent"; label: string } {
  if (!p.online) return { tone: "grey", label: "Offline" };
  if (exit) return { tone: "accent", label: p.direct ? "Direct" : "Via relay" };
  if (p.direct) return { tone: "green", label: "Direct" };
  if (p.relay_url) return { tone: "amber", label: "Via relay" };
  return { tone: "grey", label: "No path" };
}

/// The panel that slides in beside the map: everything about one device and
/// everything that can be done to it.
export function DevicePanel({
  name,
  status,
  env,
  busy,
  act,
  history,
  sends,
  onSend,
  ssh,
  goto,
  onClose,
}: {
  name: string;
  status: Status;
  env: Environment;
  busy: boolean;
  act: Act;
  history: History;
  sends: Send[];
  onSend: (peer: string, paths: string[]) => void;
  ssh: (peer: string) => void;
  goto: (p: Page) => void;
  onClose: () => void;
}) {
  const peer = name === "self" ? null : status.peers.find((p) => p.name === name);
  return (
    <aside className="slide-in flex w-[360px] shrink-0 flex-col border-l border-line bg-panel/50">
      {peer ? (
        <PeerPanel
          key={peer.name}
          peer={peer}
          status={status}
          busy={busy}
          act={act}
          history={history[peer.name] ?? []}
          sends={sends.filter((s) => s.peer === peer.name)}
          onSend={onSend}
          ssh={ssh}
          onClose={onClose}
        />
      ) : (
        <SelfPanel status={status} env={env} busy={busy} act={act} goto={goto} onClose={onClose} />
      )}
    </aside>
  );
}

function PanelHead({ children, onClose }: { children: React.ReactNode; onClose: () => void }) {
  return (
    <div className="flex items-start gap-3 px-5 pb-4 pt-5">
      <div className="min-w-0 flex-1">{children}</div>
      <IconButton onClick={onClose} title="Close (Esc)" size="sm">
        <Icon.Close size={14} />
      </IconButton>
    </div>
  );
}

/// One of the four square buttons under a device's name.
function Action({ icon, label, onClick, disabled, busy, title }: { icon: React.ReactNode; label: string; onClick: () => void; disabled?: boolean; busy?: boolean; title?: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled || busy}
      title={title}
      className="flex h-[62px] flex-col items-center justify-center gap-1.5 rounded-xl bg-raised text-[11.5px] font-medium text-ink shadow-[var(--shadow-sm)] transition
        hover:bg-raised-2 active:translate-y-px disabled:cursor-not-allowed disabled:opacity-40"
    >
      <span className="text-dim">{busy ? <Spinner className="!size-4" /> : icon}</span>
      {label}
    </button>
  );
}

function PeerPanel({
  peer,
  status,
  busy,
  act,
  history,
  sends,
  onSend,
  ssh,
  onClose,
}: {
  peer: Peer;
  status: Status;
  busy: boolean;
  act: Act;
  history: number[];
  sends: Send[];
  onSend: (peer: string, paths: string[]) => void;
  ssh: (peer: string) => void;
  onClose: () => void;
}) {
  const [ping, setPing] = useState<Ping | null>(null);
  const [pinging, setPinging] = useState(false);
  const copy = useCopy();

  const direct = ping ? ping.direct : peer.direct;
  const latency = ping ? (ping.direct ? ping.latency : ping.relay_latency) : peer.latency;
  const isExit = status.exit_node === peer.name;
  const name = fqdn(peer.name, status);
  const host = name ?? peer.address;
  const r = reach({ ...peer, direct }, isExit);
  const web = peer.services?.find((s) => s.scheme);

  async function probe() {
    setPinging(true);
    try {
      setPing(await api.ping(peer.name));
    } catch {
      // The panel already says what it knows; the next poll corrects it.
    } finally {
      setPinging(false);
    }
  }

  async function pick() {
    if (!inTauri) {
      onSend(peer.name, ["/Users/you/Desktop/notes.txt"]);
      return;
    }
    const { open } = await import("@tauri-apps/plugin-dialog");
    const chosen = await open({ multiple: true, directory: false, title: `Send to ${peer.name}` });
    if (chosen) onSend(peer.name, Array.isArray(chosen) ? chosen : [chosen]);
  }

  return (
    <>
      <PanelHead onClose={onClose}>
        <div className="flex items-center gap-2.5">
          <Dot tone={r.tone} live={peer.online} />
          <h2 className="display truncate text-[21px]">{peer.name}</h2>
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-1.5 pl-[18px] text-[12.5px] text-dim">
          <span>{r.label}</span>
          {peer.online && latency > 0 && <span className="tabular font-mono text-[11.5px] text-dimmer">{ms(latency)}</span>}
          {isExit ? <Tag tone="accent">Your exit</Tag> : peer.exit_node ? <Tag>Exit</Tag> : null}
        </div>
      </PanelHead>

      <div className="grid grid-cols-4 gap-2 px-5">
        <Action icon={<Icon.Terminal size={18} />} label="SSH" onClick={() => ssh(peer.name)} disabled={!peer.online} title="Open a shell on this device in your terminal" />
        <Action icon={<Icon.Pulse size={18} />} label="Ping" onClick={probe} busy={pinging} title="Probe the path to this device" />
        <Action icon={<Icon.Send size={18} />} label="Send file" onClick={pick} disabled={!peer.online} title="Send a file to this device's inbox" />
        {web ? (
          <Action icon={<Icon.Open size={18} />} label={web.name ?? "Open"} onClick={() => openExternal(`${web.scheme}://${host}:${web.port}`)} title={`${web.scheme}://${host}:${web.port}`} />
        ) : (
          <Action icon={<Icon.Copy size={18} />} label="Copy IP" onClick={() => copy(peer.address)} />
        )}
      </div>

      <div className="min-h-0 flex-1 space-y-6 overflow-y-auto px-5 pb-8 pt-6">
        {peer.online && (
          <Card className="px-4 py-3.5">
            <div className="flex items-end justify-between gap-3">
              <div>
                <div className="caps text-dimmer">Latency</div>
                <div className="tabular mt-1 font-mono text-[22px] font-medium leading-none tracking-tight">
                  {latency > 0 ? ms(latency) : "—"}
                </div>
              </div>
              <Sparkline values={history} width={150} height={34} className={direct ? "text-green" : "text-amber"} />
            </div>
            <div className="mt-3 flex items-center gap-1.5 border-t border-line pt-2.5 text-[11.5px] text-dim">
              {direct ? <Icon.ArrowRight size={12} /> : <Icon.Relay size={12} />}
              <span className="selectable truncate font-mono text-[11px]">{ping?.path ?? peer.path}</span>
            </div>
          </Card>
        )}

        <Section title="Addresses">
          <Card>
            {name && <Row value={name} caption="Name on the network" mono right={<CopyButton value={name} />} />}
            <Row value={peer.address} caption="Address" mono right={<CopyButton value={peer.address} />} />
            <Row value={`makima ssh ${peer.name}`} caption="From a terminal" mono right={<CopyButton value={`makima ssh ${peer.name}`} what="the command" />} />
          </Card>
        </Section>

        {peer.services && peer.services.length > 0 && (
          <Section title={`Services · ${peer.services.length}`}>
            <Card>
              {peer.services.map((s) => {
                const url = s.scheme ? `${s.scheme}://${host}:${s.port}` : null;
                return (
                  <Row
                    key={s.port}
                    value={s.name ?? `port ${s.port}`}
                    caption={<span className="font-mono text-[11px]">{url ?? `${host}:${s.port}`}</span>}
                    right={
                      url ? (
                        <Button size="sm" icon={<Icon.Open size={13} />} onClick={() => openExternal(url)}>
                          Open
                        </Button>
                      ) : (
                        <CopyButton value={`${host}:${s.port}`} />
                      )
                    }
                  />
                );
              })}
            </Card>
          </Section>
        )}

        <Section title="Send files">
          <button
            type="button"
            data-drop-peer={peer.name}
            data-drop-disabled={!peer.online}
            onClick={pick}
            disabled={!peer.online}
            className="flex w-full flex-col items-center justify-center rounded-xl border border-dashed border-line-2 px-5 py-6 text-center transition hover:border-dimmer hover:bg-raised/60 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Icon.Upload size={20} className="text-dimmer" />
            <p className="mt-2 text-[12.5px] text-dim">
              {peer.online ? (
                <>
                  Drop files here, or on <b className="font-medium text-ink">{peer.name}</b> in the map
                </>
              ) : (
                `${peer.name} is offline`
              )}
            </p>
            {peer.online && <p className="mt-0.5 text-[11.5px] text-dimmer">They land in its inbox</p>}
          </button>
          {sends.length > 0 && (
            <ul className="space-y-1 pt-1">
              {sends.map((e) => (
                <li key={e.id} className="flex items-center gap-2 px-1 text-[12px]">
                  {e.state === "sending" ? (
                    <Spinner className="text-dim" />
                  ) : e.state === "ok" ? (
                    <Icon.Check className="text-green" size={14} />
                  ) : (
                    <Icon.Warn className="text-red" size={14} />
                  )}
                  <span className="truncate text-dim">
                    {e.state === "failed" ? `${e.file}: ${e.note}` : e.state === "sending" ? `Sending ${e.file}…` : `Sent ${e.file}`}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Section>

        {peer.exit_node && (
          <Section title="Exit node">
            <Card>
              <Row
                value={isExit ? "Your internet goes through here" : "Offers to carry your internet traffic"}
                caption={isExit ? "Stop to use your own connection again" : "Useful on a network you don't trust"}
                right={
                  <Button
                    size="sm"
                    variant={isExit ? "danger" : "default"}
                    busy={busy}
                    onClick={() => act({ kind: "exit-node", name: isExit ? "" : peer.name })}
                  >
                    {isExit ? "Stop" : "Use"}
                  </Button>
                }
              />
            </Card>
          </Section>
        )}
      </div>
    </>
  );
}

/// How long ago an RFC 3339 time was, in the largest two units.
export function since(iso: string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (!isFinite(s)) return "";
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m`;
  return "just now";
}

function SelfPanel({ status, env, busy, act, goto, onClose }: { status: Status; env: Environment; busy: boolean; act: Act; goto: (p: Page) => void; onClose: () => void }) {
  const name = fqdn(status.node.name, status);
  const services = status.services ?? [];
  const online = status.peers.filter((p) => p.online).length;
  const role = env.holds_mesh
    ? "Holds the network"
    : status.serverless
      ? "Paired directly"
      : status.server
        ? `Joined through ${hostOf(status.server)}`
        : "Static network";

  return (
    <>
      <PanelHead onClose={onClose}>
        <div className="flex items-center gap-2.5">
          <Iris size={22} />
          <h2 className="display truncate text-[21px]">{status.node.name}</h2>
          <Tag tone="accent">This device</Tag>
        </div>
        <div className="mt-1 pl-[32px] text-[12.5px] text-dim">
          {role} · up {since(status.since)}
        </div>
      </PanelHead>

      <div className="grid grid-cols-3 gap-2 px-5">
        <Stat label="Reachable" value={`${online}/${status.peers.length}`} />
        <Stat label="Sharing" value={String(services.length)} onClick={() => goto("services")} />
        <Stat label="Received" value={String(status.inbox.received)} onClick={status.inbox.dir ? () => openFolder(status.inbox.dir!) : undefined} />
      </div>

      <div className="min-h-0 flex-1 space-y-6 overflow-y-auto px-5 pb-8 pt-6">
        <Section title="Addresses">
          <Card>
            {name && <Row value={name} caption="Name on the network" mono right={<CopyButton value={name} />} />}
            <Row value={status.node.address} caption={`Address · ${status.node.interface}`} mono right={<CopyButton value={status.node.address} />} />
          </Card>
        </Section>

        <Section
          title="Shared from here"
          right={
            <button type="button" onClick={() => goto("services")} className="text-[12px] font-medium text-dim transition hover:text-ink">
              Manage →
            </button>
          }
        >
          <Card>
            {services.length === 0 ? (
              <p className="px-4 py-3.5 text-[12.5px] leading-relaxed text-dim">
                Nothing yet. Anything listening on 127.0.0.1 is shared on its own as it starts.
              </p>
            ) : (
              services.map((s) => (
                <div key={s.port} className="flex items-center gap-2.5 border-b border-line px-4 py-2.5 last:border-0">
                  <Dot tone={!s.listening ? "red" : s.target_up ? "green" : "amber"} size="sm" />
                  <span className="truncate text-[13px]">{s.name ?? `port ${s.port}`}</span>
                  <span className="font-mono text-[11.5px] text-dimmer">:{s.port}</span>
                  <span className="ml-auto text-[11.5px] text-dim">{!s.target_up && s.listening ? "nothing behind it" : s.total ? `${s.total} conn.` : ""}</span>
                </div>
              ))
            )}
          </Card>
        </Section>

        <Section title="Incoming files">
          <Card>
            <Row
              icon={<Icon.Folder />}
              value={status.inbox.active ? (status.inbox.dir ?? "On") : "Off"}
              caption={status.inbox.active ? "Where files other devices send you land" : "This device does not accept files"}
              mono={status.inbox.active}
              right={
                status.inbox.active && status.inbox.dir ? (
                  <Button size="sm" onClick={() => openFolder(status.inbox.dir!)}>
                    Open
                  </Button>
                ) : undefined
              }
            />
          </Card>
        </Section>

        <Section title="Exit node">
          <Card>
            <Row
              icon={<Icon.Exit />}
              value="Offer this device"
              caption={
                status.node.advertises_exit
                  ? status.node.exit_approved
                    ? "Others can send their traffic through here"
                    : "Offered; waiting for the network to confirm"
                  : "Let others browse through this connection"
              }
              right={<Toggle on={status.node.advertises_exit} busy={busy} label="Offer this device as an exit node" onChange={(next) => act({ kind: "advertise-exit", on: next })} />}
            />
          </Card>
        </Section>

        <Section title="SSH">
          <Card>
            <Row
              icon={<Icon.Key />}
              value={status.ssh.active ? `Built-in server · port ${status.ssh.addr?.split(":").pop() ?? "2222"}` : "The system's sshd"}
              caption={
                status.ssh.active
                  ? `As ${status.ssh.user ?? "you"} · ${status.ssh.keys} key${status.ssh.keys === 1 ? "" : "s"} accepted`
                  : `Others reach this one with makima ssh ${status.node.name}`
              }
              right={status.ssh.fingerprint ? <CopyButton value={status.ssh.fingerprint} label="Copy host key fingerprint" what="the host key fingerprint" /> : undefined}
            />
          </Card>
          {status.ssh.fingerprint && (
            <p className="px-1 text-[11px] text-dimmer">
              <Copyable value={status.ssh.fingerprint} what="the host key fingerprint" className="font-mono">
                {status.ssh.fingerprint}
              </Copyable>
            </p>
          )}
        </Section>
      </div>
    </>
  );
}

function Stat({ label, value, onClick }: { label: string; value: string; onClick?: () => void }) {
  const inner = (
    <>
      <div className="tabular font-mono text-[18px] font-medium leading-none">{value}</div>
      <div className="caps mt-1.5 text-dimmer">{label}</div>
    </>
  );
  const cls = "flex h-[62px] flex-col items-center justify-center rounded-xl bg-raised shadow-[var(--shadow-sm)]";
  return onClick ? (
    <button type="button" onClick={onClick} className={`${cls} transition hover:bg-raised-2`}>
      {inner}
    </button>
  ) : (
    <div className={cls}>{inner}</div>
  );
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
