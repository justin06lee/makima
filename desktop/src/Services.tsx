import { useMemo, useState } from "react";
import { fqdn, openExternal, type Status } from "./api";
import type { Act, Nav } from "./App";
import { Button, Card, Dot, Input, PageHeader, Search, Section, Tag, useCopied } from "./ui";
import { Icon } from "./icons";
import { Avatar } from "./Avatar";
import { labelOf, usePrefs } from "./prefs";

/// Everything every device offers, in one place — so opening Grafana on the
/// server is one click from anywhere, without remembering which machine it is
/// on — and what this one shares, with the way to share more.
export function Services({ status, busy, act, nav }: { status: Status; busy: boolean; act: Act; nav: Nav }) {
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();
  const prefs = usePrefs();

  const remote = useMemo(
    () =>
      status.peers
        .flatMap((p) =>
          (p.services ?? []).map((s) => {
            const host = fqdn(p.name, status) ?? p.address;
            return {
              key: `${p.name}:${s.port}`,
              name: s.name ?? `port ${s.port}`,
              port: s.port,
              device: p.name,
              deviceLabel: labelOf(prefs, p.name),
              online: p.online,
              url: s.scheme ? `${s.scheme}://${host}:${s.port}` : null,
              address: `${host}:${s.port}`,
            };
          }),
        )
        .filter((s) => !q || s.name.toLowerCase().includes(q) || s.device.toLowerCase().includes(q) || s.deviceLabel.toLowerCase().includes(q) || String(s.port).includes(q))
        .sort((a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name)),
    [status, q, prefs],
  );

  const mine = (status.services ?? []).filter((s) => !q || (s.name ?? "").toLowerCase().includes(q) || String(s.port).includes(q));

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <PageHeader title="Services" sub="What your devices share with each other" right={<Search value={query} onChange={setQuery} placeholder="Filter" className="w-[180px]" />} />
      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[720px] space-y-8 px-6 pb-10 pt-6">
          <Section title="On your network" hint="Click one to open it; services without a web page copy their address.">
            {remote.length === 0 ? (
              <Card>
                <p className="px-4 py-5 text-[12.5px] leading-relaxed text-dim">
                  {q ? `Nothing matches “${query}”.` : "No other device shares anything yet. When one starts a dev server, a database or Ollama, it shows up here on its own."}
                </p>
              </Card>
            ) : (
              <Card>
                {remote.map(({ key, ...s }) => (
                  <RemoteRow key={key} {...s} onDevice={() => nav.device(s.device)} />
                ))}
              </Card>
            )}
          </Section>

          <Section title={`Shared from ${labelOf(prefs, status.node.name)}`} hint="Anything listening on localhost is shared on its own as it starts. Share a port by hand if it isn't.">
            <Card>
              {mine.map((s) => {
                const health = !s.listening ? "red" : s.target_up ? "green" : "amber";
                return (
                  <div key={s.port} className="group flex min-h-[52px] items-center gap-3 border-b border-line px-4 py-2 last:border-0">
                    <Dot tone={health} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 text-[13px]">
                        <span className="truncate font-medium">{s.name ?? `port ${s.port}`}</span>
                        <span className="font-mono text-[11.5px] text-dimmer">:{s.port}</span>
                        {s.auto && <Tag>Auto</Tag>}
                      </div>
                      <div className={`mt-px truncate text-[12px] ${health === "green" ? "text-dim" : "font-medium text-ink-2"}`}>
                        {!s.listening
                          ? s.error ?? "Not listening on the network"
                          : !s.target_up
                            ? `Nothing is answering at ${s.target}`
                            : <span className="font-mono text-[11.5px]">→ {s.target}</span>}
                      </div>
                    </div>
                    {s.total > 0 && (
                      <span className="tabular hidden text-right text-[11.5px] leading-tight text-dimmer sm:block">
                        {s.total} connection{s.total === 1 ? "" : "s"}
                        {s.active > 0 && <span className="block text-ink-2">{s.active} open</span>}
                      </span>
                    )}
                    <Button size="sm" variant="ghost" busy={busy} onClick={() => act({ kind: "deny", port: s.port })} title="Take this off the network, and keep it off">
                      Stop sharing
                    </Button>
                  </div>
                );
              })}
              <ShareRow busy={busy} act={act} empty={mine.length === 0} />
            </Card>
          </Section>
        </div>
      </div>
    </div>
  );
}

function RemoteRow({
  name,
  port,
  device,
  deviceLabel,
  online,
  url,
  address,
  onDevice,
}: {
  name: string;
  port: number;
  device: string;
  deviceLabel: string;
  online: boolean;
  url: string | null;
  address: string;
  onDevice: () => void;
}) {
  const [copied, copy] = useCopied();
  const go = () => (url ? openExternal(url) : copy(address, address));
  return (
    <div
      role="button"
      tabIndex={online ? 0 : -1}
      onClick={() => online && go()}
      onKeyDown={(e) => e.key === "Enter" && online && go()}
      className={`group flex min-h-[52px] items-center gap-3 border-b border-line px-4 py-2 transition-colors last:border-0 ${online ? "cursor-pointer hover:bg-hover" : "opacity-50"}`}
    >
      <span className="flex size-8 shrink-0 items-center justify-center rounded-lg border border-line bg-sunken text-dim" title={url ? "A web page" : "A TCP service"}>
        {url ? <Icon.Globe size={15} /> : <Icon.Plug size={15} />}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 text-[13px]">
          <span className="truncate font-medium">{name}</span>
          <span className="font-mono text-[11.5px] text-dimmer">:{port}</span>
        </div>
        <div className="mt-px flex min-w-0 items-center gap-1.5 text-[12px] text-dim">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              onDevice();
            }}
            className="inline-flex shrink-0 items-center gap-1.5 hover:text-ink hover:underline"
          >
            <Avatar name={device} size={14} offline={!online} />
            {deviceLabel}
          </button>
          <span className="text-dimmer">·</span>
          <span className="truncate font-mono text-[11.5px] text-dimmer">{url ?? address}</span>
        </div>
      </div>
      <span className={`flex shrink-0 items-center gap-1 text-[12px] font-medium transition-opacity ${copied ? "text-ink" : "text-dim opacity-0 group-hover:opacity-100"}`}>
        {url ? (
          <>
            Open <Icon.Open size={14} />
          </>
        ) : copied ? (
          <>
            Copied <Icon.Check size={14} />
          </>
        ) : (
          <>
            Copy <Icon.Copy size={14} />
          </>
        )}
      </span>
    </div>
  );
}

/// The last row: a port number and a button.
function ShareRow({ busy, act, empty }: { busy: boolean; act: Act; empty: boolean }) {
  const [port, setPort] = useState("");
  const n = Number(port);
  const valid = Number.isInteger(n) && n >= 1 && n <= 65535;

  function share() {
    if (!valid) return;
    act({ kind: "allow", port: n });
    setPort("");
  }

  return (
    <div className={`flex items-center gap-3 px-4 py-3 ${empty ? "" : "bg-sunken/50"}`}>
      <span className="flex size-[7px] shrink-0" />
      <div className="min-w-0 flex-1 text-[12.5px] text-dim">{empty ? "Nothing shared yet. Share a port:" : "Share another port"}</div>
      <Input value={port} onChange={(v) => setPort(v.replace(/\D/g, "").slice(0, 5))} placeholder="3000" inputMode="numeric" onEnter={share} className="!h-7 !w-[84px] text-center" mono />
      <Button size="sm" variant="primary" onClick={share} busy={busy} disabled={!valid} icon={<Icon.Plus size={14} />}>
        Share
      </Button>
    </div>
  );
}
