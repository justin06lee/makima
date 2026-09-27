import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { api, ms, type Environment, type Peer, type Status } from "./api";
import type { Act, History, Page } from "./App";
import { Button, Dot, Search, Segmented, Tag } from "./ui";
import { Icon } from "./icons";
import { Iris } from "./Iris";
import { DevicePanel, reach, type Send } from "./Device";
import { useFileDrop } from "./useDrop";
import { useToast } from "./toast";

/// Where the choice between the map and the list is remembered.
const VIEW = "makima:mesh-view";

/// The network, drawn the way makima's mark is: this device is the pupil, and
/// every other device sits on a ring around it. The ring says how it is
/// reached — the inner one directly, the middle one through the relay, the
/// outer one not at all — so how the network is doing can be read from across
/// the room. A device keeps its bearing as it moves between rings, so the
/// picture changes only when something about it does.
export function Mesh({
  status,
  env,
  busy,
  act,
  history,
  selected,
  setSelected,
  onAdd,
  ssh,
  goto,
}: {
  status: Status;
  env: Environment;
  busy: boolean;
  act: Act;
  history: History;
  selected: string | null;
  setSelected: (s: string | null) => void;
  onAdd: () => void;
  ssh: (peer: string) => void;
  goto: (p: Page) => void;
}) {
  const [view, setView] = useState<"map" | "list">(() => (localStorage.getItem(VIEW) === "list" ? "list" : "map"));
  const [sends, setSends] = useState<Send[]>([]);
  const nextSend = useRef(1);
  const toast = useToast();

  useEffect(() => localStorage.setItem(VIEW, view), [view]);

  // A device that leaves the network takes its selection with it.
  useEffect(() => {
    if (selected && selected !== "self" && !status.peers.some((p) => p.name === selected)) setSelected(null);
  }, [status.peers, selected, setSelected]);

  const peers = useMemo(() => [...status.peers].sort((a, b) => a.name.localeCompare(b.name)), [status.peers]);

  const send = useCallback(
    async (peer: string, paths: string[]) => {
      for (const path of paths) {
        const file = path.split(/[\\/]/).pop() ?? path;
        const id = nextSend.current++;
        setSends((l) => [{ id, peer, file, state: "sending" as const }, ...l].slice(0, 12));
        let ok = false;
        let note: string | undefined;
        try {
          const out = await api.sendFile(peer, path);
          ok = out.ok;
          note = out.ok ? undefined : out.output;
        } catch (e) {
          note = String(e);
        }
        setSends((l) => l.map((s) => (s.id === id ? { ...s, state: ok ? "ok" : "failed", note } : s)));
        toast(ok ? `Sent ${file} to ${peer}` : `${file} was not sent: ${note}`, ok ? "ok" : "error");
      }
    },
    [toast],
  );

  const { dragging, over } = useFileDrop(send);

  // Up and down walk the devices; Escape puts the panel away.
  const order = useMemo(() => ["self", ...[...peers].sort((a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name)).map((p) => p.name)], [peers]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (t.closest("input, textarea, [role=dialog]") || e.metaKey || e.ctrlKey) return;
      if (e.key === "Escape") setSelected(null);
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const i = selected ? order.indexOf(selected) : -1;
        const n = e.key === "ArrowDown" ? (i + 1) % order.length : (i - 1 + order.length) % order.length;
        setSelected(order[n]);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [order, selected, setSelected]);

  return (
    <div className="flex min-w-0 flex-1">
      <div className="grain relative min-w-0 flex-1 overflow-hidden">
        {view === "map" ? (
          <MeshMap status={status} peers={peers} selected={selected} onSelect={setSelected} over={over} dragging={dragging} onAdd={onAdd} />
        ) : (
          <DeviceList status={status} peers={peers} selected={selected} onSelect={setSelected} over={over} history={history} />
        )}

        <div className="pointer-events-none absolute inset-x-4 top-4 flex items-start justify-between">
          <div className="pointer-events-auto">
            <Segmented
              size="sm"
              value={view}
              onChange={setView}
              options={[
                { value: "map", label: <Icon.Mesh size={14} />, title: "Map" },
                { value: "list", label: <Icon.List size={14} />, title: "List" },
              ]}
            />
          </div>
          {view === "map" && !selected && status.peers.length > 0 && (
            <p className="fade-in pt-1.5 text-[11.5px] text-dimmer">Choose a device for details · drop a file on one to send it</p>
          )}
        </div>

        {view === "map" && status.peers.length > 0 && <Legend />}

        {dragging && (
          <div className="fade-in pointer-events-none absolute inset-x-0 bottom-5 flex justify-center">
            <div className="flex items-center gap-2 rounded-full bg-ink px-4 py-2 text-[12.5px] font-medium text-bg shadow-[var(--shadow)]">
              <Icon.Send size={14} />
              {over ? `Let go to send to ${over}` : "Drop onto a device to send"}
            </div>
          </div>
        )}
      </div>

      {selected && (
        <DevicePanel
          key={selected === "self" ? "self" : "peer"}
          name={selected}
          status={status}
          env={env}
          busy={busy}
          act={act}
          history={history}
          sends={sends}
          onSend={send}
          ssh={ssh}
          goto={goto}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}

function Legend() {
  return (
    <div className="pointer-events-none absolute bottom-4 left-4 flex items-center gap-4 rounded-lg bg-bg/70 px-3 py-2 text-[11px] text-dim backdrop-blur-sm">
      <span className="flex items-center gap-1.5">
        <svg width="18" height="6" aria-hidden="true"><line x1="0" y1="3" x2="18" y2="3" stroke="var(--green)" strokeWidth="1.6" /></svg>
        Direct
      </span>
      <span className="flex items-center gap-1.5">
        <svg width="18" height="6" aria-hidden="true"><line x1="0" y1="3" x2="18" y2="3" stroke="var(--amber)" strokeWidth="1.6" strokeDasharray="3 3" /></svg>
        Relayed
      </span>
      <span className="flex items-center gap-1.5">
        <svg width="8" height="8" aria-hidden="true"><circle cx="4" cy="4" r="3" fill="none" stroke="var(--dimmer)" strokeWidth="1.4" /></svg>
        Offline
      </span>
      <span className="flex items-center gap-1.5">
        <svg width="18" height="6" aria-hidden="true"><line x1="0" y1="3" x2="18" y2="3" stroke="var(--accent)" strokeWidth="2" /></svg>
        Exit route
      </span>
    </div>
  );
}

type Placed = { peer: Peer; x: number; y: number; ring: 0 | 1 | 2 };

function MeshMap({
  status,
  peers,
  selected,
  onSelect,
  over,
  dragging,
  onAdd,
}: {
  status: Status;
  peers: Peer[];
  selected: string | null;
  onSelect: (s: string | null) => void;
  over: string | null;
  dragging: boolean;
  onAdd: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 0, h: 0 });
  const [hover, setHover] = useState<string | null>(null);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setSize({ w: e.contentRect.width, h: e.contentRect.height }));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const { w, h } = size;
  const cx = w / 2;
  const cy = h / 2 + 8;
  // Room is left outside the last ring for the names under the dots.
  const R = Math.max(90, Math.min(w - 150, h - 110) / 2);
  const radii = [R * 0.44, R * 0.72, R];
  const labels = ["Direct", "Relayed", "Offline"];

  const placed: Placed[] = peers.map((peer, i) => {
    // Evenly round the circle by name, starting just off the top, so every
    // device has a bearing of its own that does not move when others change.
    const a = -Math.PI / 2 + ((i + 0.5) * 2 * Math.PI) / peers.length;
    const ring: Placed["ring"] = !peer.online ? 2 : peer.direct || !peer.relay_url ? 0 : 1;
    const r = radii[ring];
    return { peer, ring, x: cx + Math.cos(a) * r, y: cy + Math.sin(a) * r };
  });

  const selfR = 38;

  return (
    <div ref={ref} className="absolute inset-0" onClick={() => onSelect(null)}>
      {w > 0 && (
        <>
          <svg width={w} height={h} className="absolute inset-0" aria-hidden="true">
            {/* The dial round the outside, like the marks round the icon. */}
            <g opacity="0.9">
              {Array.from({ length: 72 }, (_, i) => {
                const a = (i * Math.PI) / 36;
                const major = i % 9 === 0;
                const r0 = R + 18;
                const r1 = r0 + (major ? 9 : 4);
                return (
                  <line
                    key={i}
                    x1={cx + Math.cos(a) * r0}
                    y1={cy + Math.sin(a) * r0}
                    x2={cx + Math.cos(a) * r1}
                    y2={cy + Math.sin(a) * r1}
                    stroke={major ? "var(--dimmer)" : "var(--line-2)"}
                    strokeWidth={major ? 1.4 : 1}
                  />
                );
              })}
            </g>

            <circle cx={cx} cy={cy} r={radii[0]} fill="none" stroke="var(--line-2)" strokeWidth="1" />
            <circle cx={cx} cy={cy} r={radii[1]} fill="none" stroke="var(--line-2)" strokeWidth="1" strokeDasharray="3 5" />
            <circle cx={cx} cy={cy} r={radii[2]} fill="none" stroke="var(--line-2)" strokeWidth="1" strokeDasharray="1 6" strokeLinecap="round" />

            {peers.length > 0 &&
              radii.map((r, i) => (
                <text
                  key={i}
                  x={cx}
                  y={cy - r + 3.5}
                  textAnchor="middle"
                  className="caps"
                  fill="var(--dimmer)"
                  stroke="var(--bg)"
                  strokeWidth="5"
                  paintOrder="stroke"
                  style={{ fontSize: 9 }}
                >
                  {labels[i]}
                </text>
              ))}

            {placed.map(({ peer, x, y }) => {
              if (!peer.online) return null;
              const dx = x - cx;
              const dy = y - cy;
              const d = Math.hypot(dx, dy) || 1;
              const x0 = cx + (dx / d) * selfR;
              const y0 = cy + (dy / d) * selfR;
              const x1 = x - (dx / d) * 10;
              const y1 = y - (dy / d) * 10;
              const isExit = status.exit_node === peer.name;
              const lit = hover === peer.name || selected === peer.name || over === peer.name;
              const colour = isExit ? "var(--accent)" : peer.direct ? "var(--green)" : "var(--amber)";
              return (
                <g key={peer.name} style={{ transition: "opacity 200ms" }} opacity={hover && !lit ? 0.35 : 1}>
                  <line
                    x1={x0}
                    y1={y0}
                    x2={x1}
                    y2={y1}
                    stroke={colour}
                    strokeOpacity={lit || isExit ? 0.9 : 0.45}
                    strokeWidth={isExit ? 2 : lit ? 1.8 : 1.3}
                    strokeDasharray={peer.direct ? undefined : "4 4"}
                  />
                  {/* Packets: a short dash running out along the line. */}
                  <line
                    x1={x0}
                    y1={y0}
                    x2={x1}
                    y2={y1}
                    stroke={colour}
                    strokeWidth={isExit ? 3 : 2.4}
                    strokeLinecap="round"
                    strokeDasharray="2 38"
                    className={peer.direct ? "flow" : "flow-slow"}
                  />
                </g>
              );
            })}
          </svg>

          {/* This device, in the middle. Its name sits above it: devices are
              spread from just off the top, so nothing is ever straight up. */}
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              onSelect(selected === "self" ? null : "self");
            }}
            className="group absolute flex flex-col items-center"
            style={{ left: cx, top: cy, transform: "translate(-50%, calc(-100% + 38px))" }}
            title="This device"
          >
            <span className="display rounded-md bg-bg/80 px-1.5 text-[13.5px] leading-tight">{status.node.name}</span>
            <span className="tabular mb-2 rounded bg-bg/80 px-1 font-mono text-[10.5px] text-dim">{status.node.address}</span>
            <span
              className={`flex size-[76px] items-center justify-center rounded-full bg-bg transition
                ${selected === "self" ? "shadow-[0_0_0_2px_var(--accent),0_0_0_8px_var(--focus)]" : "shadow-[0_0_0_1px_var(--line-2)] group-hover:shadow-[0_0_0_1px_var(--dimmer)]"}`}
            >
              <Iris size={60} />
            </span>
          </button>

          {placed.map((p) => (
            <Node
              key={p.peer.name}
              p={p}
              exit={status.exit_node === p.peer.name}
              selected={selected === p.peer.name}
              over={over === p.peer.name}
              dragging={dragging}
              dim={!!hover && hover !== p.peer.name}
              onHover={setHover}
              onSelect={() => onSelect(selected === p.peer.name ? null : p.peer.name)}
            />
          ))}

          {peers.length === 0 && (
            <div className="absolute inset-x-0 flex flex-col items-center text-center" style={{ top: cy + 70 }}>
              <p className="display text-[16px]">Only this device so far</p>
              <p className="mt-1 max-w-[300px] text-[12.5px] leading-relaxed text-dim">
                Add a laptop, a server, a Raspberry Pi — each one lands on these rings as it joins.
              </p>
              <Button
                variant="primary"
                className="mt-4"
                icon={<Icon.Plus size={14} />}
                kbd="⌘N"
                onClick={() => {
                  onAdd();
                }}
              >
                Add a device
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function Node({
  p,
  exit,
  selected,
  over,
  dragging,
  dim,
  onHover,
  onSelect,
}: {
  p: Placed;
  exit: boolean;
  selected: boolean;
  over: boolean;
  dragging: boolean;
  dim: boolean;
  onHover: (name: string | null) => void;
  onSelect: () => void;
}) {
  const { peer } = p;
  const r = reach(peer, exit);
  const fill = { green: "bg-green", amber: "bg-amber", accent: "bg-accent", grey: "" }[r.tone];
  const droppable = dragging && peer.online;
  return (
    <div className="absolute left-0 top-0 transition-transform duration-700 ease-[cubic-bezier(0.2,0.8,0.2,1)]" style={{ transform: `translate(${p.x}px, ${p.y}px)` }}>
      <button
        type="button"
        data-drop-peer={peer.name}
        data-drop-disabled={!peer.online}
        onClick={(e) => {
          e.stopPropagation();
          onSelect();
        }}
        onMouseEnter={() => onHover(peer.name)}
        onMouseLeave={() => onHover(null)}
        className={`group absolute flex -translate-x-1/2 flex-col items-center rounded-xl px-2 pb-1.5 pt-0 transition-opacity duration-200 ${dim ? "opacity-45" : ""}`}
        style={{ top: -9 }}
      >
        <span className="relative flex size-[18px] items-center justify-center">
          {peer.online && <span className={`ping-ring absolute inset-[3px] rounded-full ${fill}`} />}
          <span
            className={`relative rounded-full transition-all duration-200
              ${peer.online ? `${fill} size-3 shadow-[0_0_0_3px_var(--bg)]` : "size-3 border-[1.5px] border-dimmer bg-bg"}
              ${selected ? "!shadow-[0_0_0_3px_var(--bg),0_0_0_5px_var(--ink)]" : ""}
              ${over ? "scale-[1.8] !shadow-[0_0_0_3px_var(--bg),0_0_0_5px_var(--accent)]" : droppable ? "scale-125" : "group-hover:scale-125"}`}
          />
        </span>
        <span
          className={`mt-1 flex items-center gap-1 whitespace-nowrap rounded-md px-1.5 py-px text-[12.5px] font-semibold leading-tight transition
            ${selected ? "bg-ink text-bg" : `bg-bg/85 ${peer.online ? "text-ink" : "text-dim"}`}`}
        >
          {peer.name}
          {exit && <Tag tone="accent">exit</Tag>}
        </span>
        <span className="tabular mt-0.5 whitespace-nowrap rounded bg-bg/85 px-1 font-mono text-[10.5px] leading-tight text-dim">
          {!peer.online ? "offline" : peer.latency > 0 ? `${peer.direct ? "" : "relay · "}${ms(peer.latency)}` : r.label.toLowerCase()}
        </span>
      </button>
    </div>
  );
}

/// The same devices as rows, for when there are more of them than a circle
/// shows well, or for reading down a column of addresses.
function DeviceList({
  status,
  peers,
  selected,
  onSelect,
  over,
  history,
}: {
  status: Status;
  peers: Peer[];
  selected: string | null;
  onSelect: (s: string | null) => void;
  over: string | null;
  history: History;
}) {
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();
  const rows = [...peers]
    .filter((p) => !q || p.name.toLowerCase().includes(q) || p.address.includes(q) || p.services?.some((s) => s.name?.toLowerCase().includes(q)))
    .sort((a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name));
  const selfMatches = !q || status.node.name.toLowerCase().includes(q) || status.node.address.includes(q);
  // Path and services give way first when the device panel narrows the list.
  const grid =
    "grid grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)_64px] @[560px]:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_minmax(0,0.9fr)_72px_64px] items-center gap-3";
  const wide = "hidden @[560px]:block";

  return (
    <div className="@container absolute inset-0 overflow-y-auto px-5 pb-6 pt-16">
      <div className="mb-3 max-w-[280px]">
        <Search value={query} onChange={setQuery} placeholder="Filter by name, address or service" />
      </div>
      <div className={`${grid} caps px-3 pb-2 text-dimmer`}>
        <span>Device</span>
        <span>Address</span>
        <span className={wide}>Path</span>
        <span className="text-right">Latency</span>
        <span className={`${wide} text-right`}>Services</span>
      </div>
      <div className="overflow-hidden rounded-xl bg-raised shadow-[var(--shadow-sm)]">
        {selfMatches && (
          <ListRow grid={grid} active={selected === "self"} onClick={() => onSelect(selected === "self" ? null : "self")}>
            <span className="flex min-w-0 items-center gap-2.5">
              <Iris size={12} />
              <span className="truncate font-semibold">{status.node.name}</span>
              <Tag tone="accent">you</Tag>
            </span>
            <span className="truncate font-mono text-[11.5px] text-dim">{status.node.address}</span>
            <span className={`${wide} text-[12px] text-dim`}>This device</span>
            <span />
            <span className={`${wide} text-right font-mono text-[11.5px] text-dim`}>{status.services?.length ?? 0}</span>
          </ListRow>
        )}
        {rows.map((p) => {
          const exit = status.exit_node === p.name;
          const r = reach(p, exit);
          const recent = (history[p.name] ?? []).filter((v) => v > 0);
          return (
            <ListRow key={p.name} grid={grid} active={selected === p.name} over={over === p.name} drop={p.name} dropDisabled={!p.online} onClick={() => onSelect(selected === p.name ? null : p.name)}>
              <span className="flex min-w-0 items-center gap-2.5">
                <Dot tone={r.tone} size="sm" />
                <span className={`truncate font-semibold ${p.online ? "" : "text-dim"}`}>{p.name}</span>
                {exit ? <Tag tone="accent">exit</Tag> : p.exit_node ? <Tag>exit</Tag> : null}
              </span>
              <span className="truncate font-mono text-[11.5px] text-dim">{p.address}</span>
              <span className={`${wide} text-[12px] text-dim`}>{r.label}</span>
              <span className="tabular text-right font-mono text-[11.5px] text-dim">{p.online ? ms(recent[recent.length - 1] ?? p.latency) || "—" : "—"}</span>
              <span className={`${wide} text-right font-mono text-[11.5px] text-dim`}>{p.services?.length ?? 0}</span>
            </ListRow>
          );
        })}
        {rows.length === 0 && !selfMatches && <p className="px-4 py-4 text-[12.5px] text-dim">Nothing matches “{query}”.</p>}
      </div>
    </div>
  );
}

function ListRow({
  grid,
  active,
  over,
  drop,
  dropDisabled,
  onClick,
  children,
}: {
  grid: string;
  active: boolean;
  over?: boolean;
  drop?: string;
  dropDisabled?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      role="option"
      aria-selected={active}
      data-drop-peer={drop}
      data-drop-disabled={dropDisabled}
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      className={`${grid} w-full border-b border-line px-3 py-2.5 text-left text-[13px] transition last:border-0
        ${over ? "bg-accent/10 shadow-[inset_2px_0_0_var(--accent)]" : active ? "bg-ink/6 shadow-[inset_2px_0_0_var(--ink)]" : "hover:bg-raised-2"}`}
    >
      {children}
    </button>
  );
}
