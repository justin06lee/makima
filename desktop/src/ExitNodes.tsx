import { ms, type Status } from "./api";
import type { Act } from "./App";
import { Card, Dot, Row, Section, Spinner, Toggle } from "./ui";
import { Icon } from "./icons";
import { reach } from "./Device";

/// Pick a device to carry all of this one's internet traffic, or none.
///
/// The route is drawn before it is chosen, because "exit node" is a phrase
/// that means nothing until it is seen: this device, then the one it goes
/// through, then the internet.
export function ExitNodes({ status, busy, act }: { status: Status; busy: boolean; act: Act }) {
  const offering = status.peers.filter((p) => p.exit_node).sort((a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name));
  const current = status.exit_node ?? "";
  const via = status.peers.find((p) => p.name === current);

  return (
    <div className="grain min-w-0 flex-1 overflow-y-auto">
      <div className="fade-in mx-auto w-full max-w-[640px] space-y-8 px-7 pb-10 pt-7">
        <header>
          <h1 className="display text-[26px] leading-none">Exit node</h1>
          <p className="mt-2 max-w-[520px] text-[13px] leading-relaxed text-dim">
            Send all of this device's internet traffic through another of your devices — so a laptop on café wifi
            browses from home, and the café sees only a tunnel.
          </p>
        </header>

        <Route from={status.node.name} via={via?.name} busy={busy} />

        <Section title="Go out through">
          <Card>
            <Choice
              icon={<Icon.Globe size={16} />}
              label="This device's own connection"
              caption="No exit node — traffic goes out wherever this device is"
              checked={current === ""}
              busy={busy}
              onPick={() => act({ kind: "exit-node", name: "" })}
            />
            {offering.map((p) => {
              const r = reach(p);
              return (
                <Choice
                  key={p.name}
                  icon={<Icon.Server size={16} />}
                  label={p.name}
                  caption={
                    <span className="flex items-center gap-1.5">
                      <Dot tone={r.tone} size="sm" />
                      {r.label}
                      {p.online && p.latency > 0 && <span className="tabular font-mono text-[11px] text-dimmer">{ms(p.latency)}</span>}
                      <span className="font-mono text-[11px] text-dimmer">{p.address}</span>
                    </span>
                  }
                  checked={current === p.name}
                  busy={busy}
                  disabled={!p.online && current !== p.name}
                  onPick={() => act({ kind: "exit-node", name: p.name })}
                />
              );
            })}
          </Card>
          {offering.length === 0 && (
            <p className="px-1 text-[12.5px] leading-relaxed text-dim">
              None of your devices offers to be an exit node yet. On the one that should — a machine at home that
              stays on — open makima, click it in the middle of the map, and switch on <b className="font-medium text-ink">Offer this device</b>.
            </p>
          )}
        </Section>

        <Section title="This device">
          <Card>
            <Row
              icon={<Icon.Exit />}
              value="Offer this device as an exit node"
              caption={
                status.node.advertises_exit
                  ? status.node.exit_approved
                    ? "Your other devices can send their traffic through this one"
                    : "Offered — waiting for the network to confirm it"
                  : "Let your other devices browse through this connection"
              }
              right={<Toggle on={status.node.advertises_exit} busy={busy} label="Offer this device as an exit node" onChange={(next) => act({ kind: "advertise-exit", on: next })} />}
            />
          </Card>
        </Section>
      </div>
    </div>
  );
}

/// This device → the exit → the internet, drawn.
function Route({ from, via, busy }: { from: string; via?: string; busy: boolean }) {
  const hops = via ? 3 : 2;
  return (
    <div className="relative overflow-hidden rounded-2xl bg-raised px-6 py-7 shadow-[var(--shadow-sm)]">
      {/* The wire between the hops, level with the middle of their circles. */}
      <svg className="absolute left-[46px] top-[46px] h-2" style={{ width: "calc(100% - 92px)" }} aria-hidden="true">
        <line x1="0" y1="4" x2="100%" y2="4" stroke={via ? "var(--accent)" : "var(--line-2)"} strokeWidth={via ? 2 : 1.5} strokeDasharray={via ? undefined : "4 5"} />
        {via && <line x1="0" y1="4" x2="100%" y2="4" stroke="var(--accent)" strokeWidth="3.5" strokeLinecap="round" strokeDasharray="2 38" className="flow" />}
      </svg>
      <div className={`relative grid items-start ${hops === 3 ? "grid-cols-3" : "grid-cols-2"}`}>
        <Hop icon={<Icon.Laptop size={20} />} label={from} caption="This device" align="start" />
        {via && <Hop icon={busy ? <Spinner className="!size-5" /> : <Icon.Server size={20} />} label={via} caption="Exit node" align="center" accent />}
        <Hop icon={<Icon.Globe size={20} />} label="Internet" caption={via ? `Sees ${via}'s address` : "Sees this device's address"} align="end" />
      </div>
    </div>
  );
}

function Hop({ icon, label, caption, align, accent }: { icon: React.ReactNode; label: string; caption: string; align: "start" | "center" | "end"; accent?: boolean }) {
  const a = { start: "items-start text-left", center: "items-center text-center", end: "items-end text-right" }[align];
  return (
    <div className={`flex flex-col ${a}`}>
      <span
        className={`flex size-11 items-center justify-center rounded-full bg-bg ${accent ? "text-accent shadow-[0_0_0_2px_var(--accent),0_0_0_7px_var(--focus)]" : "text-ink shadow-[0_0_0_1px_var(--line-2)]"}`}
      >
        {icon}
      </span>
      <span className="display mt-2.5 max-w-[160px] truncate text-[14px]">{label}</span>
      <span className="text-[11.5px] text-dim">{caption}</span>
    </div>
  );
}

function Choice({
  icon,
  label,
  caption,
  checked,
  busy,
  disabled,
  onPick,
}: {
  icon: React.ReactNode;
  label: string;
  caption: React.ReactNode;
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
      className={`flex w-full items-center gap-3 border-b border-line px-4 py-3 text-left transition last:border-0 disabled:cursor-default
        ${checked ? "bg-accent/6" : "enabled:hover:bg-raised-2"}`}
    >
      <span className={`flex size-8 shrink-0 items-center justify-center rounded-lg ${checked ? "bg-accent text-accent-ink" : "bg-raised-2 text-dim"}`}>{icon}</span>
      <span className={`min-w-0 flex-1 ${disabled && !checked ? "opacity-45" : ""}`}>
        <span className="block truncate text-[13.5px] font-medium text-ink">{label}</span>
        <span className="mt-0.5 block truncate text-[12px] text-dim">{caption}</span>
      </span>
      <span className={`flex size-[18px] shrink-0 items-center justify-center rounded-full border-[1.5px] transition ${checked ? "border-accent bg-accent" : "border-line-2"}`}>
        {checked && <span className="size-1.5 rounded-full bg-white" />}
      </span>
    </button>
  );
}
