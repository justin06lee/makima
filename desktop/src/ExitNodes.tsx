import { ms, type Status } from "./api";
import type { Act } from "./App";
import { Card, PageHeader, Section, Signal, Spinner, Toggle } from "./ui";
import { Icon } from "./icons";

/// Pick a device to carry all of this one's internet traffic, or none — and
/// whether this one offers to carry the others'.
export function ExitNodes({ status, busy, act }: { status: Status; busy: boolean; act: Act }) {
  const offering = status.peers.filter((p) => p.exit_node).sort((a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name));
  const current = status.exit_node ?? "";

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <PageHeader title="Exit node" sub="Where this device's internet traffic goes out" />
      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[560px] space-y-8 px-6 pb-10 pt-6">
          <Route from={status.node.name} via={current} />

          <Section title="Route traffic through" hint="Browse from another device's connection — a laptop on café wifi, through your home line.">
            <Card>
              <Choice
                label="No exit node"
                caption="Use this device's own connection"
                icon={<Icon.Home size={15} />}
                checked={current === ""}
                busy={busy}
                onPick={() => act({ kind: "exit-node", name: "" })}
              />
              {offering.map((p) => (
                <Choice
                  key={p.name}
                  label={p.name}
                  caption={
                    <span className="flex items-center gap-2">
                      <Signal latency={p.latency} direct={p.direct} online={p.online} />
                      {p.online ? (p.direct ? "Direct" : "Via relay") : "Offline"}
                      {p.online && p.latency > 0 && <span className="tabular text-dimmer">{ms(p.latency)}</span>}
                    </span>
                  }
                  icon={<Icon.Devices size={15} />}
                  checked={current === p.name}
                  busy={busy}
                  disabled={!p.online && current !== p.name}
                  onPick={() => act({ kind: "exit-node", name: p.name })}
                />
              ))}
            </Card>
            {offering.length === 0 && (
              <p className="mt-2.5 text-[12.5px] leading-relaxed text-dim">
                No other device offers to be an exit node yet. On the one that should, open makima and turn on <b className="font-medium text-ink">Offer this device</b> below.
              </p>
            )}
          </Section>

          <Section title="This device">
            <Card>
              <div className="flex min-h-[56px] items-center gap-3 px-4 py-2.5">
                <div className="min-w-0 flex-1">
                  <div className="text-[13px]">Offer {status.node.name} as an exit node</div>
                  <div className="mt-px text-[12px] leading-snug text-dim">
                    {status.node.advertises_exit
                      ? status.node.exit_approved
                        ? "Other devices can choose to send their traffic through this one."
                        : "Offered — waiting for the network to confirm it."
                      : "Lets your other devices use this one's connection when they choose to."}
                  </div>
                </div>
                <Toggle on={status.node.advertises_exit} busy={busy} label="Offer this device as an exit node" onChange={(next) => act({ kind: "advertise-exit", on: next })} />
              </div>
            </Card>
          </Section>
        </div>
      </div>
    </div>
  );
}

/// The route, drawn: this device → (the exit node) → the internet.
function Route({ from, via }: { from: string; via: string }) {
  return (
    <div className="rounded-xl border border-line bg-sunken/60 px-6 py-5">
      <div className="flex items-center">
        <Node label={from} sub="This device" icon={<Icon.Devices size={16} />} />
        <Wire live />
        {via && (
          <>
            <Node label={via} sub="Exit node" icon={<Icon.Devices size={16} />} ink />
            <Wire live />
          </>
        )}
        <Node label="Internet" sub={`Sees ${via || from}`} icon={<Icon.Globe size={16} />} />
      </div>
    </div>
  );
}

function Node({ label, sub, icon, ink }: { label: string; sub: string; icon: React.ReactNode; ink?: boolean }) {
  return (
    <div className="fade-in flex w-[96px] shrink-0 flex-col items-center text-center">
      <span className={`flex size-10 items-center justify-center rounded-xl ${ink ? "bg-primary text-primary-ink" : "border border-line-2 bg-panel text-ink-2"}`}>{icon}</span>
      <span className="mt-2 w-full truncate text-[12.5px] font-medium">{label}</span>
      <span className="w-full truncate text-[11px] text-dimmer">{sub}</span>
    </div>
  );
}

/// A line with a dot running along it: traffic is going this way.
function Wire({ live }: { live?: boolean }) {
  return (
    <div className="relative -mt-9 h-px min-w-6 flex-1 bg-line-2">
      {live && <span className="wire-dot absolute left-0 top-1/2 size-1.5 -translate-y-1/2 rounded-full bg-green" />}
    </div>
  );
}

function Choice({
  label,
  caption,
  icon,
  checked,
  busy,
  disabled,
  onPick,
}: {
  label: string;
  caption: React.ReactNode;
  icon: React.ReactNode;
  checked: boolean;
  busy: boolean;
  disabled?: boolean;
  onPick: () => void;
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={checked}
      disabled={busy || disabled || checked}
      onClick={onPick}
      className="flex min-h-[56px] w-full items-center gap-3 border-b border-line px-4 py-2.5 text-left transition-colors last:border-0 enabled:hover:bg-hover disabled:cursor-default"
    >
      <span className={`flex size-8 shrink-0 items-center justify-center rounded-lg ${checked ? "bg-primary text-primary-ink" : "bg-sunken text-dim"} ${disabled && !checked ? "opacity-50" : ""}`}>
        {icon}
      </span>
      <span className={`min-w-0 flex-1 ${disabled && !checked ? "opacity-50" : ""}`}>
        <span className="block truncate text-[13px] font-medium text-ink">{label}</span>
        <span className="mt-px block truncate text-[12px] text-dim">{caption}</span>
      </span>
      <span
        className={`flex size-[18px] shrink-0 items-center justify-center rounded-full border transition-colors
          ${checked ? "border-primary bg-primary text-primary-ink" : "border-line-2"}`}
      >
        {checked && (busy ? <Spinner className="size-2.5" /> : <Icon.Check size={11} />)}
      </span>
    </button>
  );
}
