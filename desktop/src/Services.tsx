import { useState } from "react";
import { fqdn, openExternal, type Service, type Status } from "./api";
import type { Act } from "./App";
import { Button, Card, Dot, Input, Search, Section, Tag } from "./ui";
import { Icon } from "./icons";
import { useCopy } from "./toast";

/// Everything the network offers, in one place.
///
/// This is what most people open the window for — "where is Ollama again" —
/// so every device's services are laid out together instead of one device at
/// a time, and what this device shares is managed underneath.
export function Services({ status, busy, act }: { status: Status; busy: boolean; act: Act }) {
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();

  const all = status.peers
    .flatMap((p) => (p.services ?? []).map((s) => ({ s, peer: p })))
    .filter(({ s, peer }) => !q || (s.name ?? "").toLowerCase().includes(q) || peer.name.toLowerCase().includes(q) || String(s.port).includes(q))
    .sort((a, b) => Number(b.peer.online) - Number(a.peer.online) || a.peer.name.localeCompare(b.peer.name) || a.s.port - b.s.port);

  return (
    <div className="grain min-w-0 flex-1 overflow-y-auto">
      <div className="fade-in mx-auto w-full max-w-[860px] space-y-8 px-7 pb-10 pt-7">
        <header className="flex items-end justify-between gap-6">
          <div>
            <h1 className="display text-[26px] leading-none">Services</h1>
            <p className="mt-2 text-[13px] text-dim">What your devices share with each other, and what this one shares.</p>
          </div>
          <div className="w-[240px]">
            <Search value={query} onChange={setQuery} placeholder="Find a service or device" />
          </div>
        </header>

        <Section title={`On your network · ${all.length}`}>
          {all.length === 0 ? (
            <Card className="px-5 py-6 text-center text-[13px] leading-relaxed text-dim">
              {q ? (
                <>Nothing matches “{query}”.</>
              ) : (
                <>
                  No other device shares anything yet. A service started on any of them — a dev server, Ollama, a
                  database — shows up here by itself, ready to open.
                </>
              )}
            </Card>
          ) : (
            <div className="grid grid-cols-[repeat(auto-fill,minmax(230px,1fr))] gap-3">
              {all.map(({ s, peer }) => (
                <ServiceCard key={`${peer.name}:${s.port}`} s={s} device={peer.name} online={peer.online} host={fqdn(peer.name, status) ?? peer.address} />
              ))}
            </div>
          )}
        </Section>

        <Shared status={status} busy={busy} act={act} />
      </div>
    </div>
  );
}

function ServiceCard({ s, device, online, host }: { s: Service; device: string; online: boolean; host: string }) {
  const copy = useCopy();
  const url = s.scheme ? `${s.scheme}://${host}:${s.port}` : null;
  const addr = `${host}:${s.port}`;
  const name = s.name ?? `port ${s.port}`;
  // The whole card is the button: open it if it is a web page, copy where it
  // is if it is not. The small copy button is for the address of a web page.
  const primary = () => (url ? void openExternal(url) : void copy(addr));
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={primary}
      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && primary()}
      title={url ? `Open ${url}` : `Copy ${addr}`}
      className={`group relative flex cursor-pointer flex-col rounded-xl bg-raised p-4 shadow-[var(--shadow-sm)] transition
        hover:-translate-y-px hover:shadow-[var(--shadow-sm),0_10px_28px_-14px_rgba(0,0,0,0.35)] focus-visible:shadow-[0_0_0_3px_var(--focus)] focus-visible:outline-none
        ${online ? "" : "opacity-55"}`}
    >
      <div className="flex items-start gap-3">
        <Monogram name={name} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-[14px] font-semibold leading-tight">{name}</div>
          <div className="mt-1 flex items-center gap-1.5 text-[12px] text-dim">
            <Dot tone={online ? "green" : "grey"} size="sm" />
            <span className="truncate">{device}</span>
          </div>
        </div>
        <span className="flex size-7 shrink-0 items-center justify-center rounded-lg text-dimmer transition group-hover:bg-ink group-hover:text-bg">
          {url ? <Icon.Open size={14} /> : <Icon.Copy size={14} />}
        </span>
      </div>
      <div className="mt-3.5 flex items-center gap-2 border-t border-line pt-3">
        <span className="selectable min-w-0 flex-1 truncate font-mono text-[11px] text-dim">{url ?? addr}</span>
        {url && (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              void copy(url);
            }}
            title="Copy address"
            className="text-dimmer opacity-0 transition hover:text-ink group-hover:opacity-100"
          >
            <Icon.Copy size={13} />
          </button>
        )}
      </div>
    </div>
  );
}

/// A service's initial, on a square: something to find it by at a glance.
function Monogram({ name }: { name: string }) {
  return (
    <span className="display flex size-9 shrink-0 items-center justify-center rounded-[10px] bg-ink/7 text-[15px] uppercase text-ink shadow-[inset_0_0_0_1px_var(--line)]">
      {name.replace(/^port /, "#").slice(0, 1)}
    </span>
  );
}

/// What this device shares, and the one field that shares something more.
function Shared({ status, busy, act }: { status: Status; busy: boolean; act: Act }) {
  const [port, setPort] = useState("");
  const services = status.services ?? [];

  function publish() {
    const n = Number(port);
    if (!Number.isInteger(n) || n < 1 || n > 65535) return;
    act({ kind: "allow", port: n });
    setPort("");
  }

  return (
    <Section
      title={`Shared from ${status.node.name} · ${services.length}`}
      right={
        <div className="flex items-center gap-1.5">
          <Input
            value={port}
            onChange={(v) => setPort(v.replace(/\D/g, "").slice(0, 5))}
            placeholder="port"
            inputMode="numeric"
            onEnter={publish}
            className="!h-[26px] !w-[76px] text-center"
            mono
          />
          <Button size="sm" variant="primary" onClick={publish} busy={busy} disabled={!port} icon={<Icon.Plus size={13} />}>
            Share
          </Button>
        </div>
      }
      hint="Anything listening on 127.0.0.1 is shared on its own once it has been up for a few seconds. Remove takes it off the network and keeps it off."
    >
      <Card>
        {services.length === 0 ? (
          <p className="px-4 py-4 text-[13px] text-dim">Nothing is shared from this device yet.</p>
        ) : (
          services.map((s) => {
            const tone = !s.listening ? "red" : s.target_up ? "green" : "amber";
            const state = !s.listening ? (s.error ?? "not listening") : s.target_up ? "Answering" : "Nothing is answering behind it";
            return (
              <div key={s.port} className="flex items-center gap-3 border-b border-line px-4 py-3 last:border-0">
                <Dot tone={tone} live={tone === "green" && s.active > 0} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-[13.5px] font-medium">{s.name ?? `port ${s.port}`}</span>
                    <span className="font-mono text-[11.5px] text-dimmer">:{s.port}</span>
                    {s.auto && <Tag>auto</Tag>}
                  </div>
                  <div className="mt-0.5 flex items-center gap-1.5 text-[12px] text-dim">
                    <span className={tone === "green" ? "" : tone === "amber" ? "text-amber" : "text-red"}>{state}</span>
                    <span className="text-dimmer">·</span>
                    <span className="font-mono text-[11px]">→ {s.target}</span>
                  </div>
                </div>
                <div className="tabular hidden text-right font-mono text-[11px] leading-tight text-dim sm:block">
                  <div>{s.total} total</div>
                  <div className="text-dimmer">{s.active} open{s.failed ? ` · ${s.failed} failed` : ""}</div>
                </div>
                <Button size="sm" variant="danger" busy={busy} onClick={() => act({ kind: "deny", port: s.port })} title="Take this off the network, and keep it off">
                  Remove
                </Button>
              </div>
            );
          })
        )}
      </Card>
    </Section>
  );
}
