import { useEffect, useMemo, useRef, useState } from "react";
import { copyText, fqdn, openExternal, type Status } from "./api";
import type { Act, Nav } from "./App";
import { Kbd, shortcut, toast } from "./ui";
import { Avatar } from "./Avatar";
import { labelOf, usePrefs } from "./prefs";
import { Icon } from "./icons";

type Item = {
  id: string;
  group: "Devices" | "Actions" | "Services" | "Exit node" | "Go to";
  label: string;
  hint?: string;
  icon: React.ReactNode;
  keys?: string;
  words: string;
  run: () => void;
};

/// ⌘K: every device, every service, and everything the window can do, found
/// by typing any part of it.
export function Palette({ status, running, mac, nav, act, onClose }: { status?: Status; running: boolean; mac: boolean; nav: Nav; act: Act; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const prefs = usePrefs();
  const L = (name: string) => labelOf(prefs, name);
  const [at, setAt] = useState(0);
  const list = useRef<HTMLDivElement>(null);

  const items = useMemo<Item[]>(() => {
    const out: Item[] = [];
    const s = status;
    if (running && s) {
      out.push({ id: "add", group: "Actions", label: "Add a device", icon: <Icon.Plus />, keys: shortcut(mac, "N"), words: "add device invite join new", run: nav.add });
      for (const p of [...s.peers].sort((a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name))) {
        out.push({
          id: `dev:${p.name}`,
          group: "Devices",
          label: L(p.name),
          hint: p.online ? (p.direct ? "Direct" : "Via relay") : "Offline",
          icon: <Avatar name={p.name} size={18} offline={!p.online} />,
          words: `${p.name} ${L(p.name)} ${p.address} device`,
          run: () => nav.device(p.name),
        });
        if (p.online) {
          out.push({ id: `ssh:${p.name}`, group: "Actions", label: `SSH to ${L(p.name)}`, icon: <Icon.Terminal />, words: `ssh shell terminal ${p.name} ${L(p.name)}`, run: () => nav.ssh(p.name) });
        }
        out.push({
          id: `cp:${p.name}`,
          group: "Actions",
          label: `Copy ${L(p.name)}'s address`,
          hint: p.address,
          icon: <Icon.Copy />,
          words: `copy address ip ${p.name} ${L(p.name)} ${p.address}`,
          run: () => void copyText(p.address).then(() => toast(`Copied ${p.address}`)),
        });
        for (const sv of p.services ?? []) {
          const host = fqdn(p.name, s) ?? p.address;
          const url = sv.scheme ? `${sv.scheme}://${host}:${sv.port}` : null;
          const name = sv.name ?? `port ${sv.port}`;
          out.push({
            id: `svc:${p.name}:${sv.port}`,
            group: "Services",
            label: url ? `Open ${name}` : `Copy ${name}'s address`,
            hint: `on ${L(p.name)}`,
            icon: url ? <Icon.Open /> : <Icon.Copy />,
            words: `${name} ${sv.port} ${p.name} ${L(p.name)} service open`,
            run: url ? () => void openExternal(url) : () => void copyText(`${host}:${sv.port}`).then(() => toast(`Copied ${host}:${sv.port}`)),
          });
        }
        if (p.exit_node && p.online && s.exit_node !== p.name) {
          out.push({ id: `exit:${p.name}`, group: "Exit node", label: `Route traffic through ${L(p.name)}`, icon: <Icon.Globe />, words: `exit node route vpn ${p.name} ${L(p.name)}`, run: () => void act({ kind: "exit-node", name: p.name }) });
        }
      }
      if (s.exit_node) {
        out.push({ id: "exit:none", group: "Exit node", label: "Stop using an exit node", hint: `now ${L(s.exit_node)}`, icon: <Icon.Home />, words: "exit node stop none off own connection", run: () => void act({ kind: "exit-node", name: "" }) });
      }
      out.push({
        id: "copy:self",
        group: "Actions",
        label: "Copy this device's address",
        hint: s.node.address,
        icon: <Icon.Copy />,
        words: `copy my address ip self ${s.node.name} ${s.node.address}`,
        run: () => void copyText(s.node.address).then(() => toast(`Copied ${s.node.address}`)),
      });
      out.push({ id: "down", group: "Actions", label: "Disconnect", icon: <Icon.Power />, words: "disconnect off down stop", run: () => void act({ kind: "down" }) });
      out.push({ id: "go:devices", group: "Go to", label: "Devices", icon: <Icon.Devices />, keys: shortcut(mac, "1"), words: "devices go", run: () => nav.page("devices") });
      out.push({ id: "go:services", group: "Go to", label: "Services", icon: <Icon.Services />, keys: shortcut(mac, "2"), words: "services go share port", run: () => nav.page("services") });
      out.push({ id: "go:exit", group: "Go to", label: "Exit node", icon: <Icon.Exit />, keys: shortcut(mac, "3"), words: "exit node go", run: () => nav.page("exit") });
      out.push({ id: "edit:self", group: "Actions", label: "Rename this device", icon: <Icon.Pencil />, words: "rename name picture photo avatar edit this device", run: () => nav.edit(s.node.name) });
      out.push({ id: "go:settings", group: "Go to", label: "Settings", icon: <Icon.Gear />, keys: shortcut(mac, ","), words: "settings preferences diagnostics go", run: () => nav.page("settings") });
    } else {
      out.push({ id: "up", group: "Actions", label: "Connect", icon: <Icon.Power />, words: "connect on up start", run: () => void act({ kind: "up" }) });
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status, running, mac, nav, act, prefs]);

  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  const shown = useMemo(() => {
    const hits = items.filter((it) => terms.every((t) => `${it.label} ${it.words}`.toLowerCase().includes(t)));
    // With nothing typed, devices and the common actions — not every copy
    // and open the mesh could offer.
    if (terms.length === 0) return hits.filter((it) => it.group === "Devices" || it.group === "Go to" || it.id === "add").slice(0, 14);
    const order = ["Devices", "Actions", "Services", "Exit node", "Go to"];
    return hits.sort((a, b) => order.indexOf(a.group) - order.indexOf(b.group)).slice(0, 30);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items, query]);

  useEffect(() => setAt(0), [query]);
  useEffect(() => {
    list.current?.querySelector<HTMLElement>(`[data-i="${at}"]`)?.scrollIntoView({ block: "nearest" });
  }, [at]);

  function choose(i: number) {
    const it = shown[i];
    if (!it) return;
    onClose();
    it.run();
  }

  function onKey(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setAt((a) => Math.min(shown.length - 1, a + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setAt((a) => Math.max(0, a - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      choose(at);
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    }
  }

  let last = "";
  return (
    <div className="scrim-in fixed inset-0 z-40 flex justify-center bg-black/20 px-6 pt-[12vh]" onMouseDown={onClose}>
      <div
        role="dialog"
        aria-label="Search"
        onMouseDown={(e) => e.stopPropagation()}
        className="pop-in flex h-fit max-h-[70vh] w-full max-w-[540px] flex-col overflow-hidden rounded-2xl bg-panel shadow-[var(--pop-shadow)]"
      >
        <div className="flex items-center gap-2.5 border-b border-line px-4">
          <Icon.Search className="text-dimmer" />
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onKey}
            placeholder="Search devices, services and actions…"
            spellCheck={false}
            className="selectable h-[50px] flex-1 bg-transparent text-[14px] text-ink outline-none placeholder:text-dimmer focus-visible:!shadow-none"
          />
          <Kbd>esc</Kbd>
        </div>
        <div ref={list} className="min-h-0 flex-1 overflow-y-auto p-1.5">
          {shown.length === 0 && <p className="px-3 py-6 text-center text-[12.5px] text-dim">Nothing matches.</p>}
          {shown.map((it, i) => {
            const head = it.group !== last;
            last = it.group;
            return (
              <div key={it.id}>
                {head && <div className="px-2.5 pb-1 pt-2.5 text-[11px] font-medium text-dimmer">{it.group}</div>}
                <button
                  type="button"
                  role="option"
                  aria-selected={i === at}
                  data-i={i}
                  onMouseMove={() => setAt(i)}
                  onClick={() => choose(i)}
                  className={`flex h-9 w-full items-center gap-3 rounded-lg px-2.5 text-left text-[13px] ${i === at ? "bg-active text-ink" : "text-ink-2"}`}
                >
                  <span className="flex size-4 items-center justify-center text-dim">{it.icon}</span>
                  <span className="min-w-0 flex-1 truncate">{it.label}</span>
                  {it.hint && <span className="truncate text-[11.5px] text-dimmer">{it.hint}</span>}
                  {it.keys && <Kbd>{it.keys}</Kbd>}
                </button>
              </div>
            );
          })}
        </div>
        <div className="flex items-center gap-4 border-t border-line bg-sunken/50 px-4 py-2 text-[11px] text-dimmer">
          <span className="flex items-center gap-1.5">
            <Kbd>↑</Kbd>
            <Kbd>↓</Kbd> to move
          </span>
          <span className="flex items-center gap-1.5">
            <Kbd>↵</Kbd> to choose
          </span>
        </div>
      </div>
    </div>
  );
}
