import { ms, type Status } from "./api";
import type { Act } from "./App";
import { Card, Code, Dot } from "./ui";
import { Icon } from "./icons";

/// Pick a device to carry all of this one's internet traffic, or none.
export function ExitNodes({ status, busy, act }: { status: Status; busy: boolean; act: Act }) {
  const offering = status.peers.filter((p) => p.exit_node);
  const current = status.exit_node ?? "";

  return (
    <div className="fade-in mx-auto w-full max-w-[560px] space-y-6 px-6 pb-8 pt-5">
      <div>
        <h1 className="text-[22px] font-semibold tracking-tight">Exit nodes</h1>
        <p className="mt-1.5 text-[13px] leading-relaxed text-dim">
          Send all of this device's internet traffic through another device on your network — so a laptop on
          café wifi browses from home.
        </p>
      </div>

      <Card>
        <Choice
          label="None"
          caption="Use this device's own connection"
          checked={current === ""}
          busy={busy}
          onPick={() => act({ kind: "exit-node", name: "" })}
        />
        {offering.map((p) => (
          <Choice
            key={p.name}
            label={p.name}
            caption={
              <span className="flex items-center gap-1.5">
                <Dot tone={p.online ? "green" : "grey"} size="sm" />
                {p.online ? (p.direct ? "Direct" : "Via relay") : "Offline"}
                {p.online && p.latency > 0 && <span className="text-dimmer">{ms(p.latency)}</span>}
                <span className="font-mono text-dimmer">{p.address}</span>
              </span>
            }
            checked={current === p.name}
            busy={busy}
            disabled={!p.online && current !== p.name}
            onPick={() => act({ kind: "exit-node", name: p.name })}
          />
        ))}
      </Card>

      {offering.length === 0 && (
        <div className="space-y-2 text-[13px] leading-relaxed text-dim">
          <p>No device is offering to be an exit node yet. On the one that should, run:</p>
          <Code>makima set -advertise-exit-node true</Code>
          <p>
            then approve it on the device holding the network with{" "}
            <span className="font-mono">makima-server routes approve</span>.
          </p>
        </div>
      )}

      {status.node.advertises_exit && (
        <p className="text-[12.5px] text-dim">
          This device offers to be an exit node{status.node.exit_approved ? "." : ", and is waiting to be approved."}
        </p>
      )}
    </div>
  );
}

function Choice({
  label,
  caption,
  checked,
  busy,
  disabled,
  onPick,
}: {
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
      className="flex w-full items-center gap-3 border-b border-line px-4 py-3 text-left transition last:border-0 enabled:hover:bg-card-2 disabled:cursor-default"
    >
      <span
        className={`flex size-[18px] shrink-0 items-center justify-center rounded-full border transition
          ${checked ? "border-accent bg-accent text-accent-ink" : "border-line-2 bg-bg"}`}
      >
        {checked && <Icon.Check size={12} />}
      </span>
      <span className={`min-w-0 flex-1 ${disabled && !checked ? "opacity-50" : ""}`}>
        <span className="block truncate text-[14px] text-ink">{label}</span>
        <span className="mt-0.5 block truncate text-[12px] text-dim">{caption}</span>
      </span>
    </button>
  );
}
