import { useEffect, useMemo, useState } from "react";
import { api, fqdn, inTauri, ms, openExternal, openFolder, pathLabel, type Environment, type Peer, type Ping, type Status } from "./api";
import type { Act } from "./App";
import { Button, Card, CopyButton, Dot, Input, Row, Search, Section, Spinner } from "./ui";
import { Icon } from "./icons";
import { useDrop } from "./useDrop";

/// The list on the left and the one thing it selects on the right.
export function Devices({
  status,
  env,
  busy,
  act,
  onAdd,
}: {
  status: Status;
  env: Environment;
  busy: boolean;
  act: Act;
  onAdd: () => void;
}) {
  const [selected, setSelected] = useState<string>("self");
  const [query, setQuery] = useState("");

  // A device that leaves the network takes its selection with it.
  useEffect(() => {
    if (selected !== "self" && !status.peers.some((p) => p.name === selected)) setSelected("self");
  }, [status.peers, selected]);

  const q = query.trim().toLowerCase();
  const peers = useMemo(
    () =>
      [...status.peers]
        .filter((p) => !q || p.name.toLowerCase().includes(q) || p.address.includes(q))
        .sort((a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name)),
    [status.peers, q],
  );
  const selfMatches = !q || status.node.name.toLowerCase().includes(q) || status.node.address.includes(q);

  const peer = selected === "self" ? null : status.peers.find((p) => p.name === selected) ?? null;

  return (
    <>
      <aside className="flex w-[272px] shrink-0 flex-col border-r border-line">
        <div className="px-4 pb-3 pt-5">
          <h1 className="text-[22px] font-semibold tracking-tight">Devices</h1>
          <div className="mt-3">
            <Search value={query} onChange={setQuery} />
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-2 pb-3">
          {selfMatches && (
            <>
              <GroupLabel>This device</GroupLabel>
              <DeviceRow
                name={status.node.name}
                address={status.node.address}
                online
                active={selected === "self"}
                onClick={() => setSelected("self")}
              />
            </>
          )}

          <GroupLabel>{status.domain ? `${status.domain} network` : "Network"}</GroupLabel>
          {peers.length === 0 ? (
            <div className="px-2.5 py-3 text-[12.5px] leading-relaxed text-dim">
              {q ? (
                "Nothing matches."
              ) : (
                <>
                  <p>No other devices yet.</p>
                  <button type="button" onClick={onAdd} className="mt-1 font-medium text-accent hover:underline">
                    Add one
                  </button>
                </>
              )}
            </div>
          ) : (
            peers.map((p) => (
              <DeviceRow
                key={p.name}
                name={p.name}
                address={p.address}
                online={p.online}
                exit={status.exit_node === p.name}
                active={selected === p.name}
                onClick={() => setSelected(p.name)}
              />
            ))
          )}
        </div>
      </aside>

      <div className="min-w-0 flex-1 overflow-y-auto">
        {peer ? (
          <PeerDetail key={peer.name} peer={peer} status={status} busy={busy} act={act} />
        ) : (
          <SelfDetail status={status} env={env} busy={busy} act={act} />
        )}
      </div>
    </>
  );
}

function GroupLabel({ children }: { children: React.ReactNode }) {
  return <div className="px-2.5 pb-1 pt-3 text-[12px] font-semibold text-dim">{children}</div>;
}

function DeviceRow({
  name,
  address,
  online,
  exit,
  active,
  onClick,
}: {
  name: string;
  address: string;
  online: boolean;
  exit?: boolean;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      role="option"
      aria-selected={active}
      onClick={onClick}
      className={`flex w-full items-start gap-2.5 rounded-lg px-2.5 py-2 text-left transition
        ${active ? "bg-accent text-accent-ink" : "hover:bg-card"}`}
    >
      <span className="mt-[7px]">
        <Dot tone={online ? "green" : "grey"} />
      </span>
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-1.5">
          <span className="truncate text-[13.5px] font-medium">{name}</span>
          {exit && (
            <span className={`rounded px-1 text-[10px] font-semibold uppercase tracking-wide ${active ? "bg-white/20" : "bg-card-2 text-dim"}`}>
              exit
            </span>
          )}
        </span>
        <span className={`block truncate font-mono text-[12px] ${active ? "text-accent-ink/80" : "text-dim"}`}>{address}</span>
      </span>
    </button>
  );
}

function Header({ title, tag, children }: { title: string; tag?: string; children?: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="min-w-0">
        <h1 className="flex items-center gap-2 text-[22px] font-semibold tracking-tight">
          <span className="truncate">{title}</span>
          {tag && <span className="rounded-md bg-card-2 px-1.5 py-0.5 text-[11px] font-medium text-dim">{tag}</span>}
        </h1>
      </div>
      {children && <div className="flex shrink-0 items-center gap-1.5 pt-1">{children}</div>}
    </div>
  );
}

function StatusLine({ tone, children }: { tone: "green" | "grey" | "amber"; children: React.ReactNode }) {
  return (
    <div className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-[13px] text-dim">
      <Dot tone={tone} />
      {children}
    </div>
  );
}

/// Another machine: how it is reached, what it offers, and a place to drop a
/// file for it.
function PeerDetail({ peer, status, busy, act }: { peer: Peer; status: Status; busy: boolean; act: Act }) {
  const [ping, setPing] = useState<Ping | null>(null);
  const [pinging, setPinging] = useState(false);

  const direct = ping ? ping.direct : peer.direct;
  const latency = ping ? (ping.direct ? ping.latency : ping.relay_latency) : peer.latency;
  const relay = ping?.relay_url ?? peer.relay_url;
  const isExit = status.exit_node === peer.name;
  const name = fqdn(peer.name, status);

  async function probe() {
    setPinging(true);
    try {
      setPing(await api.ping(peer.name));
    } catch {
      // The row already says what it knows; the next poll corrects it.
    } finally {
      setPinging(false);
    }
  }

  const ssh = () => openExternal(`ssh://${name ?? peer.address}`);

  return (
    <div className="fade-in space-y-6 px-6 pb-8 pt-5">
      <div>
        <Header title={peer.name}>
          <Button icon={<Icon.Terminal />} onClick={ssh} disabled={!peer.online} title="Open a shell on this device in your terminal">
            SSH
          </Button>
          <Button icon={<Icon.Pulse />} onClick={probe} busy={pinging} title="Probe the path to this device">
            Ping
          </Button>
        </Header>
        <StatusLine tone={peer.online ? "green" : "grey"}>
          <span>{peer.online ? "Connected" : "Offline"}</span>
          {peer.online && (
            <>
              <span className="text-dimmer">·</span>
              <span>{direct ? "Direct" : relay ? "Via relay" : pathLabel(peer)}</span>
              {latency > 0 && <span className="text-dimmer">{ms(latency)}</span>}
            </>
          )}
          {isExit && (
            <>
              <span className="text-dimmer">·</span>
              <span className="text-accent">Your exit node</span>
            </>
          )}
        </StatusLine>
      </div>

      <Section title="Addresses">
        <Card>
          {name && <Row value={name} caption="Name" mono right={<CopyButton value={name} />} />}
          <Row value={peer.address} caption="IPv4" mono right={<CopyButton value={peer.address} />} />
        </Card>
      </Section>

      {peer.services && peer.services.length > 0 && (
        <Section title="Services">
          <Card>
            {peer.services.map((s) => {
              const host = name ?? peer.address;
              const url = s.scheme ? `${s.scheme}://${host}:${s.port}` : null;
              return (
                <Row
                  key={s.port}
                  value={s.name ?? `port ${s.port}`}
                  caption={url ?? `${host}:${s.port}`}
                  right={
                    url ? (
                      <Button size="sm" icon={<Icon.Open />} onClick={() => openExternal(url)}>
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

      <Section title="Send a file">
        <DropZone peer={peer} enabled={peer.online} />
      </Section>

      {peer.exit_node && (
        <Section title="Exit node">
          <Card>
            <Row
              value={isExit ? `All of this device's internet traffic goes through ${peer.name}` : `${peer.name} offers to carry this device's internet traffic`}
              caption={isExit ? "Stop to use your own connection again." : "Useful on an untrusted network."}
              right={
                <Button
                  size="sm"
                  variant={isExit ? "danger" : "default"}
                  busy={busy}
                  onClick={() => act({ kind: "exit-node", name: isExit ? "" : peer.name })}
                >
                  {isExit ? "Stop" : "Use as exit node"}
                </Button>
              }
            />
          </Card>
        </Section>
      )}
    </div>
  );
}

/// Drag a file here, or pick one, and it lands in the peer's inbox.
function DropZone({ peer, enabled }: { peer: Peer; enabled: boolean }) {
  const [log, setLog] = useState<{ file: string; ok: boolean; note?: string }[]>([]);
  const [sending, setSending] = useState<string | null>(null);

  async function send(paths: string[]) {
    for (const path of paths) {
      const file = path.split(/[\\/]/).pop() ?? path;
      setSending(file);
      try {
        const out = await api.sendFile(peer.name, path);
        setLog((l) => [{ file, ok: out.ok, note: out.ok ? undefined : out.output }, ...l].slice(0, 6));
      } catch (e) {
        setLog((l) => [{ file, ok: false, note: String(e) }, ...l].slice(0, 6));
      } finally {
        setSending(null);
      }
    }
  }

  const dragging = useDrop(enabled ? send : null);

  async function pick() {
    if (!inTauri) {
      send(["/Users/you/Desktop/notes.txt"]);
      return;
    }
    const { open } = await import("@tauri-apps/plugin-dialog");
    const chosen = await open({ multiple: true, directory: false, title: `Send to ${peer.name}` });
    if (chosen) send(Array.isArray(chosen) ? chosen : [chosen]);
  }

  return (
    <div>
      <div
        className={`flex flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-7 text-center transition
          ${dragging ? "border-accent bg-accent/8" : "border-line-2"} ${enabled ? "" : "opacity-50"}`}
      >
        <Icon.Upload size={22} className={dragging ? "text-accent" : "text-dimmer"} />
        <p className="mt-2.5 text-[13px] text-dim">
          {sending ? (
            <span className="inline-flex items-center gap-2">
              <Spinner /> Sending {sending}…
            </span>
          ) : dragging ? (
            `Drop to send to ${peer.name}`
          ) : enabled ? (
            `Drop a file here to send it to ${peer.name}`
          ) : (
            `${peer.name} is offline`
          )}
        </p>
        <Button className="mt-3" onClick={pick} disabled={!enabled || !!sending}>
          Select a file…
        </Button>
      </div>
      {log.length > 0 && (
        <ul className="mt-2 space-y-1">
          {log.map((e, i) => (
            <li key={i} className="flex items-start gap-2 text-[12px]">
              {e.ok ? <Icon.Check className="mt-px text-green" size={14} /> : <Icon.Warn className="mt-px text-red" size={14} />}
              <span className="text-dim">
                {e.ok ? `Sent ${e.file}` : `${e.file}: ${e.note}`}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/// This machine: its addresses, what it publishes, and where files land.
function SelfDetail({ status, env, busy, act }: { status: Status; env: Environment; busy: boolean; act: Act }) {
  const [port, setPort] = useState("");
  const services = status.services ?? [];
  const name = fqdn(status.node.name, status);

  const role = env.holds_mesh
    ? "Holds the network"
    : status.serverless
      ? "Paired directly"
      : status.server
        ? `Joined via ${hostOf(status.server)}`
        : "Static network";

  function publish() {
    const n = Number(port);
    if (!Number.isInteger(n) || n < 1 || n > 65535) return;
    act({ kind: "allow", port: n });
    setPort("");
  }

  const openInbox = () => status.inbox.dir && openFolder(status.inbox.dir);

  return (
    <div className="fade-in space-y-6 px-6 pb-8 pt-5">
      <div>
        <Header title={status.node.name} tag="This device" />
        <StatusLine tone="green">
          <span>Connected</span>
          <span className="text-dimmer">·</span>
          <span>{role}</span>
          {status.relay.url && (
            <>
              <span className="text-dimmer">·</span>
              <span>Relay {status.relay.connected ? "up" : "down"}</span>
            </>
          )}
        </StatusLine>
      </div>

      <Section title="Addresses">
        <Card>
          {name && <Row value={name} caption="Name" mono right={<CopyButton value={name} />} />}
          <Row value={status.node.address} caption="IPv4" mono right={<CopyButton value={status.node.address} />} />
        </Card>
      </Section>

      <Section
        title="Published from this device"
        right={
          <div className="flex items-center gap-1.5">
            <Input value={port} onChange={(v) => setPort(v.replace(/\D/g, "").slice(0, 5))} placeholder="port" inputMode="numeric" onEnter={publish} className="!h-7 !w-20 text-center" mono />
            <Button size="sm" onClick={publish} busy={busy} disabled={!port}>
              Publish
            </Button>
          </div>
        }
      >
        <Card>
          {services.length === 0 ? (
            <p className="px-4 py-4 text-[13px] text-dim">
              Nothing yet. Anything listening on 127.0.0.1 is published on its own as it starts — a dev server, Ollama, a database.
            </p>
          ) : (
            services.map((s) => (
              <Row
                key={s.port}
                value={
                  <span className="flex items-center gap-2">
                    <Dot tone={!s.listening ? "red" : s.target_up ? "green" : "amber"} />
                    <span>{s.name ?? `port ${s.port}`}</span>
                    <span className="font-mono text-[12px] text-dim">:{s.port}</span>
                    {s.auto && <span className="rounded bg-card-2 px-1 text-[10px] font-semibold uppercase tracking-wide text-dim">auto</span>}
                  </span>
                }
                caption={!s.target_up && s.listening ? `${s.target} — nothing is answering behind it` : `→ ${s.target}${s.total ? ` · ${s.total} connection${s.total === 1 ? "" : "s"}` : ""}`}
                right={
                  <Button size="sm" busy={busy} onClick={() => act({ kind: "deny", port: s.port })} title="Take this off the network, and keep it off">
                    Remove
                  </Button>
                }
              />
            ))
          )}
        </Card>
      </Section>

      <Section title="Incoming files">
        <Card>
          <Row
            value={status.inbox.active ? status.inbox.dir ?? "On" : "Off"}
            caption={
              status.inbox.active
                ? status.inbox.received > 0
                  ? `${status.inbox.received} received since connecting`
                  : "Files other devices send you land here"
                : "This device does not accept files from other devices"
            }
            mono={status.inbox.active}
            right={
              status.inbox.active && status.inbox.dir ? (
                <Button size="sm" icon={<Icon.Folder />} onClick={openInbox}>
                  Open
                </Button>
              ) : undefined
            }
          />
        </Card>
      </Section>

      <Section title="SSH">
        <Card>
          <Row
            value={status.ssh.active ? `Built-in server on port ${status.ssh.addr?.split(":").pop() ?? "2222"}` : "Using the system's sshd, if it runs"}
            caption={
              status.ssh.active
                ? `Sessions run as ${status.ssh.user ?? "you"} · ${status.ssh.keys} key${status.ssh.keys === 1 ? "" : "s"} accepted`
                : "Other devices reach this one with: makima ssh " + status.node.name
            }
            right={status.ssh.fingerprint ? <CopyButton value={status.ssh.fingerprint} label="Copy host key fingerprint" /> : undefined}
          />
        </Card>
      </Section>
    </div>
  );
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
