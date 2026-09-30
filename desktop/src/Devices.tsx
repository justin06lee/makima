import { useEffect, useMemo, useState } from "react";
import { api, fqdn, inTauri, ms, openExternal, openFolder, type Environment, type Peer, type Ping, type Status } from "./api";
import type { Act, Nav } from "./App";
import { Button, Copyable, Dot, IconButton, PageHeader, Search, Section, Signal, Spinner, Tag, Toggle, toast, useCopied } from "./ui";
import { Icon } from "./icons";
import { useDrop } from "./useDrop";
import { Avatar } from "./Avatar";
import { Pulse } from "./Wave";
import { labelOf, usePrefs, type Prefs } from "./prefs";

const SELF = "\u0000self";

/// Every device on the network as a table you can read at a glance, and the
/// one you pick in an inspector beside it.
export function Devices({
  status,
  env,
  busy,
  act,
  nav,
  selected,
}: {
  status: Status;
  env: Environment;
  busy: boolean;
  act: Act;
  nav: Nav;
  selected: string | null;
}) {
  const [query, setQuery] = useState("");
  const prefs = usePrefs();
  const { send, sending } = useSender(prefs);

  const q = query.trim().toLowerCase();
  const matches = (name: string, address: string) => !q || name.toLowerCase().includes(q) || labelOf(prefs, name).toLowerCase().includes(q) || address.includes(q);
  const peers = useMemo(
    () =>
      [...status.peers]
        .filter((p) => matches(p.name, p.address) || p.services?.some((s) => s.name?.toLowerCase().includes(q)))
        .sort((a, b) => Number(b.online) - Number(a.online) || labelOf(prefs, a.name).localeCompare(labelOf(prefs, b.name))),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [status.peers, q, prefs],
  );
  const selfMatches = matches(status.node.name, status.node.address);

  const self = selected === SELF || selected === status.node.name;
  const peer = !self && selected ? status.peers.find((p) => p.name === selected) ?? null : null;
  const open = self || !!peer;

  // A device that leaves the network takes its selection with it.
  useEffect(() => {
    if (selected && !self && !peer) nav.device(null);
  }, [selected, self, peer, nav]);

  // Arrows walk the list, Escape closes the inspector — unless something
  // else on the screen is taking the keys.
  const order = useMemo(() => [...(selfMatches ? [SELF] : []), ...peers.map((p) => p.name)], [selfMatches, peers]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (t.closest("input, textarea, select, [role=dialog]") || document.querySelector("[role=dialog]")) return;
      if (e.key === "Escape" && selected) {
        nav.device(null);
      } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const at = order.indexOf(self ? SELF : selected ?? "");
        const next = e.key === "ArrowDown" ? Math.min(order.length - 1, at + 1) : Math.max(0, at === -1 ? 0 : at - 1);
        if (order[next]) nav.device(order[next]);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [order, selected, self, nav]);

  const online = status.peers.filter((p) => p.online).length;
  const reachable = new Set(status.peers.filter((p) => p.online).map((p) => p.name));
  const { dragging, over } = useDrop((paths, to) => reachable.has(to) && send(to, paths), peer?.online ? peer.name : null);

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <PageHeader
        title="Devices"
        sub={status.peers.length === 0 ? "Just this one so far" : `${online + 1} of ${status.peers.length + 1} online`}
        right={<Search value={query} onChange={setQuery} placeholder="Filter devices" className="w-[200px]" />}
      />

      <div className="flex min-h-0 flex-1">
        <div className="@container min-w-0 flex-1 overflow-y-auto" onClick={(e) => e.target === e.currentTarget && nav.device(null)}>
          <ColumnHeads />
          {selfMatches && (
            <SelfRow status={status} active={self} onClick={() => nav.device(self ? null : SELF)} />
          )}
          {peers.map((p) => (
            <PeerRow
              key={p.name}
              peer={p}
              status={status}
              active={selected === p.name}
              dropTarget={over === p.name}
              dragging={dragging}
              sending={sending?.peer === p.name}
              onClick={() => nav.device(selected === p.name ? null : p.name)}
              onSSH={() => nav.ssh(p.name)}
            />
          ))}
          {status.peers.length === 0 && !q && <Lonely onAdd={nav.add} />}
          {q && peers.length === 0 && !selfMatches && (
            <p className="px-5 py-8 text-center text-[12.5px] text-dim">Nothing matches “{query}”.</p>
          )}
          {status.peers.length > 0 && !open && (
            <p className="px-5 py-4 text-[11.5px] text-dimmer">
              {inTauri ? "Drop a file on a device to send it there." : "Select a device for its details."}
            </p>
          )}
        </div>

        {self && <SelfInspector key="self" status={status} env={env} busy={busy} act={act} nav={nav} onClose={() => nav.device(null)} />}
        {peer && (
          <PeerInspector
            key={peer.name}
            peer={peer}
            status={status}
            busy={busy}
            act={act}
            nav={nav}
            dragging={dragging}
            sending={sending?.peer === peer.name ? sending.file : null}
            onSend={(paths) => send(peer.name, paths)}
            onClose={() => nav.device(null)}
          />
        )}
      </div>
    </div>
  );
}

/// Sending files, one after another, with the result said at the bottom of
/// the window.
function useSender(prefs: Prefs) {
  const [sending, setSending] = useState<{ peer: string; file: string } | null>(null);
  async function send(peer: string, paths: string[]) {
    for (const path of paths) {
      const file = path.split(/[\\/]/).pop() ?? path;
      setSending({ peer, file });
      try {
        const out = await api.sendFile(peer, path);
        if (out.ok) toast(`Sent ${file} to ${labelOf(prefs, peer)}`);
        else toast(`${file}: ${out.output}`, "error");
      } catch (e) {
        toast(`${file}: ${String(e)}`, "error");
      } finally {
        setSending(null);
      }
    }
  }
  return { send, sending };
}

// The table's columns. Wide, it is name · address · connection · services;
// once the inspector takes half the room, just the name and the bars.
const GRID = "grid grid-cols-[minmax(0,1fr)_auto] @[600px]:grid-cols-[minmax(0,1.3fr)_112px_132px_minmax(0,1fr)_56px] items-center gap-x-4";

function ColumnHeads() {
  return (
    <div className={`${GRID} sticky top-0 z-10 hidden h-8 border-b border-line bg-panel/90 px-5 text-[11.5px] text-dimmer backdrop-blur @[600px]:grid`}>
      <span className="pl-[38px]">Name</span>
      <span>Address</span>
      <span>Connection</span>
      <span>Services</span>
      <span />
    </div>
  );
}

function rowClass(active: boolean, extra = "") {
  return `${GRID} relative h-[46px] w-full cursor-default border-b border-line px-5 text-left transition-colors
    ${active ? "bg-active" : "hover:bg-hover"} ${extra}`;
}

function SelfRow({ status, active, onClick }: { status: Status; active: boolean; onClick: () => void }) {
  const shared = status.services?.length ?? 0;
  return (
    <div role="option" aria-selected={active} tabIndex={-1} onClick={onClick} className={rowClass(active)}>
      <span className="flex min-w-0 items-center gap-3">
        <Avatar name={status.node.name} size={26} />
        <Name name={status.node.name} />
        <Tag>You</Tag>
      </span>
      <span className="hidden font-mono text-[12px] text-dim @[600px]:block">{status.node.address}</span>
      <span className="hidden text-[12px] text-dim @[600px]:block">This device</span>
      <span className="hidden truncate text-[12px] text-dim @[600px]:block">{shared > 0 ? `${shared} shared` : <span className="text-dimmer">—</span>}</span>
      <span className="text-right @[600px]:hidden" />
      <span className="hidden @[600px]:block" />
    </div>
  );
}

function PeerRow({
  peer,
  status,
  active,
  dropTarget,
  dragging,
  sending,
  onClick,
  onSSH,
}: {
  peer: Peer;
  status: Status;
  active: boolean;
  dropTarget: boolean;
  dragging: boolean;
  sending: boolean;
  onClick: () => void;
  onSSH: () => void;
}) {
  const isExit = status.exit_node === peer.name;
  const services = peer.services ?? [];
  return (
    <div
      role="option"
      aria-selected={active}
      tabIndex={-1}
      onClick={onClick}
      onDoubleClick={() => peer.online && onSSH()}
      data-drop-peer={peer.online ? peer.name : undefined}
      className={`group ${rowClass(active, dropTarget ? "!bg-active ring-1 ring-inset ring-ink/40" : dragging && !peer.online ? "opacity-40" : "")}`}
    >
      <span className="flex min-w-0 items-center gap-3">
        <Avatar name={peer.name} size={26} offline={!peer.online} />
        <Name name={peer.name} dim={!peer.online} />
        {isExit && <Tag tone="ink">Exit</Tag>}
        {sending && <Spinner className="text-dim" />}
      </span>
      <span className="hidden font-mono text-[12px] text-dim @[600px]:block">{peer.address}</span>
      <span className="hidden items-center gap-2 text-[12px] text-dim @[600px]:flex">
        <Signal latency={peer.latency} direct={peer.direct} online={peer.online} />
        <span className="truncate">{peer.online ? (peer.direct ? "Direct" : "Relay") : "Offline"}</span>
        {peer.online && peer.latency > 0 && <span className="tabular text-dimmer">{ms(peer.latency)}</span>}
      </span>
      <span className="hidden min-w-0 truncate text-[12px] text-dim @[600px]:block">
        {services.length === 0 ? (
          <span className="text-dimmer">—</span>
        ) : (
          <>
            {services
              .slice(0, 2)
              .map((s) => s.name ?? `:${s.port}`)
              .join(", ")}
            {services.length > 2 && <span className="text-dimmer"> +{services.length - 2}</span>}
          </>
        )}
      </span>
      {/* Narrow: the bars stand in for the whole connection column. */}
      <span className="flex items-center justify-end @[600px]:hidden">
        <Signal latency={peer.latency} direct={peer.direct} online={peer.online} />
      </span>
      <span className="hidden justify-end opacity-0 transition-opacity group-hover:opacity-100 @[600px]:flex">
        {peer.online && (
          <IconButton
            size="sm"
            title={`SSH to ${peer.name}`}
            onClick={() => {
              onSSH();
            }}
          >
            <Icon.Terminal size={14} />
          </IconButton>
        )}
      </span>
      {dropTarget && (
        <span className="pointer-events-none absolute inset-y-0 right-5 flex items-center gap-1.5 text-[12px] font-medium text-ink">
          <Icon.Send size={14} /> Drop to send
        </span>
      )}
    </div>
  );
}

/// The only device on the network: say what to do next rather than show an
/// empty table.
function Lonely({ onAdd }: { onAdd: () => void }) {
  return (
    <div className="flex flex-col items-center px-8 py-14 text-center">
      <div className="relative mb-5 h-[54px] w-[132px]">
        <span className="absolute left-0 top-1/2 flex size-[38px] -translate-y-1/2 items-center justify-center rounded-xl bg-primary text-primary-ink">
          <Icon.Devices size={18} />
        </span>
        <span className="absolute left-[46px] right-[46px] top-1/2 border-t border-dashed border-line-2" />
        <span className="absolute right-0 top-1/2 flex size-[38px] -translate-y-1/2 items-center justify-center rounded-xl border border-dashed border-line-2 text-dimmer">
          <Icon.Plus size={16} />
        </span>
      </div>
      <p className="text-[14px] font-medium">Add your next device</p>
      <p className="mt-1 max-w-[300px] text-[12.5px] leading-relaxed text-dim">
        Install makima on another computer. It shows fifteen words to type there, and the two can reach each other from then on.
      </p>
      <Button className="mt-4" variant="primary" icon={<Icon.Plus size={15} />} onClick={onAdd}>
        Add device
      </Button>
    </div>
  );
}

// --- the inspector ---------------------------------------------------------

function Inspector({ children, onClose, highlight }: { children: React.ReactNode; onClose: () => void; highlight?: React.ReactNode }) {
  return (
    <aside className="slide-in relative flex w-[316px] shrink-0 flex-col border-l border-line bg-panel">
      <div className="relative min-h-0 flex-1 space-y-6 overflow-y-auto px-5 pb-8 pt-5">
        <div className="absolute right-3 top-3.5">
          <IconButton title="Close (Esc)" onClick={onClose}>
            <Icon.Close size={15} />
          </IconButton>
        </div>
        {children}
      </div>
      {highlight}
    </aside>
  );
}

/// A device's name in the table: the one given here, and — when that is
/// different — the device's own, quieter, beside it.
function Name({ name, dim }: { name: string; dim?: boolean }) {
  const prefs = usePrefs();
  const label = labelOf(prefs, name);
  return (
    <span className="flex min-w-0 items-baseline gap-1.5">
      <span className={`truncate text-[13px] font-medium ${dim ? "text-dim" : ""}`}>{label}</span>
      {label !== name && <span className="hidden truncate font-mono text-[11px] text-dimmer @[600px]:inline">{name}</span>}
    </span>
  );
}

function Title({ name, offline, tag, onEdit, children }: { name: string; offline?: boolean; tag?: React.ReactNode; onEdit: () => void; children?: React.ReactNode }) {
  const prefs = usePrefs();
  const label = labelOf(prefs, name);
  return (
    <div className="pr-8">
      <button type="button" onClick={onEdit} title="Change the name or picture" className="group relative mb-3 block rounded-full">
        <Avatar name={name} size={56} offline={offline} />
        <span className="absolute -bottom-0.5 -right-0.5 flex size-6 items-center justify-center rounded-full border border-line bg-panel text-dim opacity-0 shadow-sm transition-opacity group-hover:opacity-100">
          <Icon.Pencil size={12} />
        </span>
      </button>
      <div className="flex items-center gap-2">
        <h2 className="selectable truncate text-[18px] font-semibold tracking-[-0.02em]">{label}</h2>
        {tag}
      </div>
      {label !== name && <div className="selectable mt-0.5 truncate font-mono text-[11.5px] text-dimmer">{name}</div>}
      <div className="mt-1.5 flex flex-wrap items-center gap-x-1.5 gap-y-1 text-[12.5px] text-dim">{children}</div>
    </div>
  );
}

function Tile({ icon, label, onClick, disabled, busy, title }: { icon: React.ReactNode; label: string; onClick: () => void; disabled?: boolean; busy?: boolean; title?: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled || busy}
      title={title}
      className="flex h-[58px] flex-col items-center justify-center gap-1.5 rounded-[10px] border border-line bg-panel text-[12px] font-medium text-ink-2 transition hover:border-line-2 hover:bg-sunken active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-40 disabled:active:scale-100"
    >
      {busy ? <Spinner className="size-4" /> : icon}
      {label}
    </button>
  );
}

function KV({ k, children }: { k: string; children: React.ReactNode }) {
  return (
    <div className="flex min-h-[34px] items-center justify-between gap-3 border-b border-line py-1.5 last:border-0">
      <span className="shrink-0 text-[12px] text-dim">{k}</span>
      <span className="flex min-w-0 flex-1 items-center justify-end text-[12.5px] text-ink">{children}</span>
    </div>
  );
}

/// Another machine: how it is reached, what it offers, and what you can do
/// with it.
function PeerInspector({
  peer,
  status,
  busy,
  act,
  nav,
  dragging,
  sending,
  onSend,
  onClose,
}: {
  peer: Peer;
  status: Status;
  busy: boolean;
  act: Act;
  nav: Nav;
  dragging: boolean;
  sending: string | null;
  onSend: (paths: string[]) => void;
  onClose: () => void;
}) {
  const [ping, setPing] = useState<Ping | null>(null);
  const [pinging, setPinging] = useState(false);

  const direct = ping ? ping.direct : peer.direct;
  const latency = ping ? (ping.direct ? ping.latency : ping.relay_latency) : peer.latency;
  const prefs = usePrefs();
  const label = labelOf(prefs, peer.name);
  const isExit = status.exit_node === peer.name;
  const name = fqdn(peer.name, status);
  const host = name ?? peer.address;

  async function probe() {
    setPinging(true);
    try {
      const p = await api.ping(peer.name);
      setPing(p);
      const l = p.direct ? p.latency : p.relay_latency;
      toast(`${label}: ${p.direct ? "direct" : "via relay"}${l ? `, ${ms(l)}` : ""}`);
    } catch {
      toast(`${label} did not answer`, "error");
    } finally {
      setPinging(false);
    }
  }

  async function pick() {
    if (!inTauri) {
      onSend(["/Users/you/Desktop/notes.txt"]);
      return;
    }
    const { open } = await import("@tauri-apps/plugin-dialog");
    const chosen = await open({ multiple: true, directory: false, title: `Send to ${label}` });
    if (chosen) onSend(Array.isArray(chosen) ? chosen : [chosen]);
  }

  return (
    <Inspector
      onClose={onClose}
      highlight={
        dragging && peer.online ? (
          <div className="fade-in pointer-events-none absolute inset-2 flex flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed border-ink/40 bg-panel/90 backdrop-blur-sm">
            <Icon.Send size={22} className="text-ink" />
            <p className="text-[13px] font-medium">Drop to send to {label}</p>
            <p className="text-[12px] text-dim">It lands in their makima inbox</p>
          </div>
        ) : null
      }
    >
      <Title name={peer.name} offline={!peer.online} onEdit={() => nav.edit(peer.name)} tag={isExit ? <Tag tone="ink">Exit</Tag> : undefined}>
        <Signal latency={latency} direct={direct} online={peer.online} />
        <span>{peer.online ? (direct ? "Direct" : "Via relay") : "Offline"}</span>
        {peer.online && latency > 0 && (
          <>
            <span className="text-dimmer">·</span>
            <span className="tabular">{ms(latency)}</span>
          </>
        )}
      </Title>

      <div className="grid grid-cols-3 gap-2">
        <Tile icon={<Icon.Terminal size={17} />} label="SSH" onClick={() => nav.ssh(peer.name)} disabled={!peer.online} title="Open a shell on it in your terminal" />
        <Tile icon={<Icon.Send size={17} />} label={sending ? "Sending…" : "Send file"} onClick={pick} disabled={!peer.online} busy={!!sending} title="Or drop a file anywhere on the window" />
        <Tile icon={<Icon.Pulse size={17} />} label="Ping" onClick={probe} busy={pinging} title="Probe the path to it" />
      </div>

      <Section title="Addresses">
        <div>
          {name && (
            <KV k="Name">
              <Copyable value={name} align="end" />
            </KV>
          )}
          <KV k="IPv4">
            <Copyable value={peer.address} align="end" />
          </KV>
          {peer.online && !direct && (ping?.relay_url ?? peer.relay_url) && (
            <KV k="Relay">
              <span className="truncate font-mono text-[12px] text-dim">{ping?.relay_url ?? peer.relay_url}</span>
            </KV>
          )}
        </div>
      </Section>

      {peer.services && peer.services.length > 0 && (
        <Section title="Services">
          <div className="-mx-2">
            {peer.services.map((s) => {
              const url = s.scheme ? `${s.scheme}://${host}:${s.port}` : null;
              return (
                <ServiceLine key={s.port} name={s.name ?? `port ${s.port}`} port={s.port} url={url} address={`${host}:${s.port}`} disabled={!peer.online} />
              );
            })}
          </div>
        </Section>
      )}

      {peer.exit_node && (
        <Section title="Exit node" hint={isExit ? "All of this device's internet traffic goes through it." : "It offers to carry this device's internet traffic."}>
          <div className="flex items-center justify-between gap-3 rounded-[10px] border border-line px-3 py-2.5">
            <span className="truncate text-[12.5px]">Route traffic through {label}</span>
            <Toggle
              on={isExit}
              busy={busy}
              disabled={!peer.online && !isExit}
              label={`Route traffic through ${label}`}
              onChange={(next) => act({ kind: "exit-node", name: next ? peer.name : "" })}
            />
          </div>
        </Section>
      )}
    </Inspector>
  );
}

export function ServiceLine({ name, port, url, address, disabled }: { name: string; port: number; url: string | null; address: string; disabled?: boolean }) {
  const [copied, copy] = useCopied();
  return (
    <div className="group flex h-[38px] items-center gap-2.5 rounded-lg px-2 transition-colors hover:bg-hover">
      <span className="min-w-0 flex-1 truncate text-[12.5px]">
        {name} <span className="font-mono text-[11.5px] text-dimmer">:{port}</span>
      </span>
      {url ? (
        <Button size="sm" variant="ghost" icon={<Icon.Open size={14} />} onClick={() => openExternal(url)} disabled={disabled} title={url}>
          Open
        </Button>
      ) : (
        <Button size="sm" variant="ghost" icon={copied ? <Icon.Check size={14} className="text-ink" /> : <Icon.Copy size={14} />} onClick={() => copy(address, address)} disabled={disabled} title={address}>
          Copy
        </Button>
      )}
    </div>
  );
}

/// This machine: its addresses, what it shares, where files land, and what
/// it offers the others.
function SelfInspector({ status, env, busy, act, nav, onClose }: { status: Status; env: Environment; busy: boolean; act: Act; nav: Nav; onClose: () => void }) {
  const services = status.services ?? [];
  const name = fqdn(status.node.name, status);

  const role = env.holds_mesh
    ? "Holds the network"
    : status.serverless
      ? "Paired directly"
      : status.server
        ? `Joined via ${hostOf(status.server)}`
        : "Static network";

  const openInbox = () => status.inbox.dir && openFolder(status.inbox.dir);

  return (
    <Inspector onClose={onClose}>
      <Title name={status.node.name} onEdit={() => nav.edit(status.node.name)} tag={<Tag>You</Tag>}>
        <Pulse on className="text-ink" />
        <span>{role}</span>
        {status.since && (
          <>
            <span className="text-dimmer">·</span>
            <span>up {uptime(status.since)}</span>
          </>
        )}
      </Title>

      <div className="grid grid-cols-3 gap-2">
        <Tile icon={<Icon.Plus size={17} />} label="Add device" onClick={nav.add} />
        <Tile icon={<Icon.Inbox size={17} />} label="Inbox" onClick={openInbox} disabled={!status.inbox.active || !status.inbox.dir} title={status.inbox.dir} />
        <Tile icon={<Icon.Services size={17} />} label="Share port" onClick={() => nav.page("services")} />
      </div>

      <Section title="Addresses">
        <div>
          {name && (
            <KV k="Name">
              <Copyable value={name} align="end" />
            </KV>
          )}
          <KV k="IPv4">
            <Copyable value={status.node.address} align="end" />
          </KV>
          <KV k="Interface">
            <span className="font-mono text-[12px] text-dim">{status.node.interface}</span>
          </KV>
        </div>
      </Section>

      <Section
        title="Sharing"
        right={
          <button type="button" onClick={() => nav.page("services")} className="text-[12px] text-dim hover:text-ink">
            Manage
          </button>
        }
      >
        {services.length === 0 ? (
          <p className="text-[12.5px] leading-relaxed text-dim">Nothing yet. Anything listening on localhost is shared on its own as it starts.</p>
        ) : (
          <div className="-mx-2">
            {services.map((s) => (
              <div key={s.port} className="flex h-[34px] items-center gap-2.5 px-2">
                <Dot tone={!s.listening ? "red" : s.target_up ? "green" : "amber"} size="sm" />
                <span className="min-w-0 flex-1 truncate text-[12.5px]">
                  {s.name ?? `port ${s.port}`} <span className="font-mono text-[11.5px] text-dimmer">:{s.port}</span>
                </span>
                {s.total > 0 && <span className="tabular text-[11.5px] text-dimmer">{s.total}</span>}
              </div>
            ))}
          </div>
        )}
      </Section>

      <Section title="Incoming files">
        <div>
          <KV k={status.inbox.active ? (status.inbox.received > 0 ? `${status.inbox.received} received` : "Folder") : "Off"}>
            {status.inbox.active && status.inbox.dir ? (
              <button type="button" onClick={openInbox} className="flex min-w-0 items-center gap-1.5 rounded-md px-1.5 py-0.5 text-dim transition-colors hover:bg-hover hover:text-ink">
                <Icon.Folder size={13} />
                <span className="truncate font-mono text-[12px]">{shortPath(status.inbox.dir)}</span>
              </button>
            ) : (
              <span className="text-dim">Not accepting files</span>
            )}
          </KV>
        </div>
      </Section>

      <Section
        title="Exit node"
        hint={
          status.node.advertises_exit
            ? status.node.exit_approved
              ? "Other devices can route their internet traffic through this one."
              : "Offered; waiting for the network to confirm."
            : "Let other devices browse from here — a laptop on café wifi, through your home connection."
        }
      >
        <div className="flex items-center justify-between gap-3 rounded-[10px] border border-line px-3 py-2.5">
          <span className="text-[12.5px]">Offer this device</span>
          <Toggle on={status.node.advertises_exit} busy={busy} label="Offer this device as an exit node" onChange={(next) => act({ kind: "advertise-exit", on: next })} />
        </div>
      </Section>

      <Section title="SSH">
        <div>
          <KV k="Server">
            <span className="text-dim">{status.ssh.active ? `Built in, port ${status.ssh.addr?.split(":").pop() ?? "2222"}` : "System sshd"}</span>
          </KV>
          {status.ssh.active && (
            <KV k="Sessions run as">
              <span className="text-dim">
                {status.ssh.user ?? "you"} · {status.ssh.keys} key{status.ssh.keys === 1 ? "" : "s"}
              </span>
            </KV>
          )}
          {status.ssh.fingerprint && (
            <KV k="Host key">
              <Copyable value={status.ssh.fingerprint} display={status.ssh.fingerprint.replace(/^SHA256:/, "").slice(0, 14) + "…"} what="the host key fingerprint" align="end" className="text-dim" />
            </KV>
          )}
        </div>
      </Section>
    </Inspector>
  );
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function shortPath(p: string): string {
  return p.replace(/^\/(Users|home)\/[^/]+/, "~");
}

/// How long ago an RFC 3339 time was, in the two largest units.
export function uptime(since: string): string {
  const s = Math.max(0, (Date.now() - new Date(since).getTime()) / 1000);
  if (!Number.isFinite(s)) return "";
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${Math.max(1, m)}m`;
}
