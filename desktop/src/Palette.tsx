import { useEffect, useMemo, useRef, useState } from "react";
import { fqdn, ms, openExternal, type Status } from "./api";
import type { Act, Page } from "./App";
import { Dot, Kbd } from "./ui";
import { Icon } from "./icons";
import { reach } from "./Device";
import { useCopy } from "./toast";

type Item = {
  id: string;
  group: "Devices" | "Services" | "Actions" | "Go to";
  label: string;
  hint?: string;
  icon: React.ReactNode;
  words: string;
  run: () => void;
};

/// ⌘K: one box that reaches everything — a device, a service on it, or
/// something to do — so nothing is more than a few letters away.
export function Palette({
  status,
  running,
  onClose,
  goto,
  select,
  ssh,
  act,
  onAdd,
}: {
  status?: Status;
  running: boolean;
  onClose: () => void;
  goto: (p: Page) => void;
  select: (name: string) => void;
  ssh: (peer: string) => void;
  act: Act;
  onAdd: () => void;
}) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const list = useRef<HTMLDivElement>(null);
  const copy = useCopy();

  const items = useMemo<Item[]>(() => {
    const out: Item[] = [];
    const peers = [...(status?.peers ?? [])].sort((a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name));
    for (const p of peers) {
      const r = reach(p, status?.exit_node === p.name);
      out.push({
        id: `dev:${p.name}`,
        group: "Devices",
        label: p.name,
        hint: `${p.address} · ${r.label}${p.online && p.latency ? ` · ${ms(p.latency)}` : ""}`,
        icon: <Dot tone={r.tone} />,
        words: `${p.name} ${p.address} device show`,
        run: () => select(p.name),
      });
    }
    for (const p of peers.filter((p) => p.online)) {
      out.push({
        id: `ssh:${p.name}`,
        group: "Actions",
        label: `SSH to ${p.name}`,
        icon: <Icon.Terminal size={15} />,
        words: `ssh shell terminal ${p.name}`,
        run: () => ssh(p.name),
      });
    }
    for (const p of peers) {
      out.push({
        id: `copy:${p.name}`,
        group: "Actions",
        label: `Copy ${p.name}'s address`,
        hint: p.address,
        icon: <Icon.Copy size={15} />,
        words: `copy address ip ${p.name} ${p.address}`,
        run: () => void copy(p.address),
      });
    }
    for (const p of peers) {
      const host = status ? (fqdn(p.name, status) ?? p.address) : p.address;
      for (const s of p.services ?? []) {
        const url = s.scheme ? `${s.scheme}://${host}:${s.port}` : null;
        out.push({
          id: `svc:${p.name}:${s.port}`,
          group: "Services",
          label: `${url ? "Open" : "Copy"} ${s.name ?? `port ${s.port}`} on ${p.name}`,
          hint: url ?? `${host}:${s.port}`,
          icon: url ? <Icon.Open size={15} /> : <Icon.Copy size={15} />,
          words: `${s.name ?? ""} ${s.port} ${p.name} service open`,
          run: () => (url ? void openExternal(url) : void copy(`${host}:${s.port}`)),
        });
      }
    }
    if (running) {
      out.push({ id: "add", group: "Actions", label: "Add a device", hint: "⌘N", icon: <Icon.Plus size={15} />, words: "add invite join new device", run: onAdd });
      for (const p of peers.filter((p) => p.exit_node && p.online && p.name !== status?.exit_node)) {
        out.push({
          id: `exit:${p.name}`,
          group: "Actions",
          label: `Send traffic through ${p.name}`,
          hint: "Exit node",
          icon: <Icon.Exit size={15} />,
          words: `exit node route vpn ${p.name}`,
          run: () => void act({ kind: "exit-node", name: p.name }),
        });
      }
      if (status?.exit_node) {
        out.push({ id: "exit:none", group: "Actions", label: "Stop using the exit node", icon: <Icon.Globe size={15} />, words: "exit node stop none off", run: () => void act({ kind: "exit-node", name: "" }) });
      }
      out.push({ id: "down", group: "Actions", label: "Disconnect this device", icon: <Icon.Power size={15} />, words: "disconnect down off stop", run: () => void act({ kind: "down" }) });
    } else {
      out.push({ id: "up", group: "Actions", label: "Connect this device", icon: <Icon.Power size={15} />, words: "connect up on start", run: () => void act({ kind: "up" }) });
    }
    const pages: [Page, string, React.ReactNode, string][] = [
      ["mesh", "Mesh", <Icon.Mesh size={15} />, "⌘1"],
      ["services", "Services", <Icon.Services size={15} />, "⌘2"],
      ["exit", "Exit node", <Icon.Exit size={15} />, "⌘3"],
      ["settings", "Settings", <Icon.Gear size={15} />, "⌘,"],
    ];
    for (const [p, label, icon, hint] of pages) {
      out.push({ id: `page:${p}`, group: "Go to", label, hint, icon, words: `go page ${label}`, run: () => goto(p) });
    }
    out.push({ id: "diag", group: "Go to", label: "Run diagnostics", icon: <Icon.Pulse size={15} />, words: "doctor diagnostics check why broken", run: () => goto("settings") });
    return out;
  }, [status, running, select, ssh, copy, act, onAdd, goto]);

  const shown = useMemo(() => {
    const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) return items.filter((i) => i.group === "Devices" || i.group === "Go to" || i.id === "add");
    return items
      .map((i) => {
        const hay = `${i.label} ${i.words}`.toLowerCase();
        if (!terms.every((t) => hay.includes(t))) return null;
        // Names that start with what was typed come first.
        const score = (i.label.toLowerCase().startsWith(terms[0]) ? 0 : 1) + (i.group === "Devices" ? 0 : 0.5);
        return { i, score };
      })
      .filter((x): x is { i: Item; score: number } => !!x)
      .sort((a, b) => a.score - b.score)
      .slice(0, 40)
      .map((x) => x.i);
  }, [items, query]);

  useEffect(() => setActive(0), [query]);

  useEffect(() => {
    list.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [active]);

  function run(i: Item | undefined) {
    if (!i) return;
    onClose();
    i.run();
  }

  // Group the results without reordering them: a heading wherever the group changes.
  let last = "";

  return (
    <div className="scrim-in fixed inset-0 z-50 flex items-start justify-center bg-black/30 px-6 pt-[12vh] backdrop-blur-[2px]" onMouseDown={onClose}>
      <div role="dialog" aria-label="Search" onMouseDown={(e) => e.stopPropagation()} className="rise w-full max-w-[560px] overflow-hidden rounded-2xl bg-bg shadow-[var(--shadow)]">
        <div className="flex items-center gap-3 border-b border-line px-4">
          <Icon.Search size={16} className="text-dimmer" />
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setActive((a) => Math.min(a + 1, shown.length - 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setActive((a) => Math.max(a - 1, 0));
              } else if (e.key === "Enter") {
                e.preventDefault();
                run(shown[active]);
              } else if (e.key === "Escape") {
                e.preventDefault();
                onClose();
              }
            }}
            placeholder="Devices, services, or something to do…"
            spellCheck={false}
            className="selectable h-[52px] flex-1 bg-transparent text-[15px] text-ink outline-none placeholder:text-dimmer focus-visible:!shadow-none"
          />
          <Kbd>esc</Kbd>
        </div>
        <div ref={list} className="max-h-[min(420px,60vh)] overflow-y-auto p-2">
          {shown.length === 0 && <p className="px-3 py-6 text-center text-[13px] text-dim">Nothing matches “{query}”.</p>}
          {shown.map((i, n) => {
            const head = i.group !== last ? i.group : null;
            last = i.group;
            return (
              <div key={i.id}>
                {head && <div className="caps px-3 pb-1 pt-2.5 text-dimmer">{head}</div>}
                <button
                  type="button"
                  data-index={n}
                  onMouseMove={() => setActive(n)}
                  onClick={() => run(i)}
                  className={`flex h-[38px] w-full items-center gap-3 rounded-lg px-3 text-left transition-colors ${n === active ? "bg-ink/8" : ""}`}
                >
                  <span className="flex w-4 shrink-0 justify-center text-dim">{i.icon}</span>
                  <span className="truncate text-[13.5px] text-ink">{i.label}</span>
                  {i.hint && <span className="ml-auto shrink-0 truncate pl-3 font-mono text-[11px] text-dimmer">{i.hint}</span>}
                  {n === active && <Icon.ArrowRight size={13} className="shrink-0 text-dim" />}
                </button>
              </div>
            );
          })}
        </div>
        <div className="flex items-center gap-4 border-t border-line bg-panel/60 px-4 py-2 text-[11px] text-dimmer">
          <span className="flex items-center gap-1.5">
            <Kbd>↑</Kbd>
            <Kbd>↓</Kbd> move
          </span>
          <span className="flex items-center gap-1.5">
            <Kbd>↵</Kbd> choose
          </span>
        </div>
      </div>
    </div>
  );
}
