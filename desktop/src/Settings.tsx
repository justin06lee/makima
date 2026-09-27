import { useEffect, useState } from "react";
import { api, inTauri, type Check, type Environment, type Status, type Tailscale } from "./api";
import type { Act } from "./App";
import { Button, Card, Code, Dot, Kbd, Row, Section, Toggle } from "./ui";
import { Icon } from "./icons";
import { TerminalSetting } from "./Terminal";

export function Settings({
  status,
  env,
  busy,
  act,
  tailscale,
  onMigrate,
}: {
  status: Status;
  env: Environment;
  busy: boolean;
  act: Act;
  tailscale: Tailscale | null;
  onMigrate: () => void;
}) {
  return (
    <div className="grain min-w-0 flex-1 overflow-y-auto">
      <div className="fade-in mx-auto w-full max-w-[620px] space-y-8 px-7 pb-10 pt-7">
        <header>
          <h1 className="display text-[26px] leading-none">Settings</h1>
          <p className="mt-2 text-[13px] text-dim">
            makima {status.version} · app {env.app_version}
          </p>
        </header>

        <Section title="General">
          <Card>
            <LoginItem />
            <TerminalSetting />
            <Row
              icon={<Icon.Command />}
              value="Command line"
              caption={env.linked ? "makima is on your PATH at /usr/local/bin/makima" : "Not on your PATH yet — terminals can't find makima"}
              right={
                env.linked ? (
                  <span className="flex items-center gap-1.5 text-[12px] text-dim">
                    <Icon.Check size={14} className="text-green" />
                    Installed
                  </span>
                ) : (
                  <Button size="sm" busy={busy} onClick={() => act({ kind: "link-cli" })}>
                    Install
                  </Button>
                )
              }
            />
          </Card>
        </Section>

        <Section title="Network">
          <Card>
            <Row
              icon={<Icon.Mesh />}
              value={env.holds_mesh ? "This device holds the network" : status.serverless ? "No server — devices pair directly" : (status.server ?? "Static network")}
              caption={
                env.holds_mesh
                  ? "Invites are made here. It runs whenever this device is on, so others can join and find each other."
                  : status.serverless
                    ? "Add devices with makima pair"
                    : "The device that holds the network"
              }
              mono={!env.holds_mesh && !status.serverless && !!status.server}
            />
            {status.relay.url && (
              <Row
                icon={<Icon.Relay />}
                value={status.relay.url}
                caption={status.relay.connected ? "Relay connected — used when no direct path can be found" : "Relay not connected"}
                mono
                right={<Dot tone={status.relay.connected ? "green" : "grey"} />}
              />
            )}
            <Row
              icon={<Icon.Globe />}
              value={status.dns_active && status.domain ? `*.${status.domain}` : "Names off"}
              caption={status.dns_active ? "Every device answers to its name" : "Reach devices by address"}
              mono={status.dns_active}
            />
            {status.firewall?.backend && status.firewall.backend !== "none" && status.firewall.backend !== "unsupported" && (
              <Row
                icon={<Icon.Shield />}
                value={`Firewall: ${status.firewall.backend === "macos" ? "macOS" : status.firewall.backend}`}
                caption={status.firewall.trusted ? "Tunnel traffic is let through" : (status.firewall.detail ?? "Tunnel traffic may be blocked")}
                right={<Dot tone={status.firewall.trusted ? "green" : "amber"} />}
              />
            )}
          </Card>
        </Section>

        {tailscale?.installed && (
          <Section title="Tailscale">
            <Card>
              <Row
                icon={<Icon.Exit />}
                value={tailscale.running ? `Running, with ${tailscale.peers} other device${tailscale.peers === 1 ? "" : "s"}` : "Installed, not connected"}
                caption={
                  tailscale.running ? "Move every device to makima through it, then take it off each one" : "Connect Tailscale to move your devices through it"
                }
                right={
                  <Button size="sm" disabled={!tailscale.running} onClick={onMigrate}>
                    Move from Tailscale…
                  </Button>
                }
              />
            </Card>
          </Section>
        )}

        <Diagnostics />

        <Section title="Keyboard">
          <Card className="grid grid-cols-2">
            {[
              ["⌘K", "Search devices, services and actions"],
              ["⌘N", "Add a device"],
              ["⌘1 ⌘2 ⌘3", "Mesh, services, exit node"],
              ["⌘,", "Settings"],
              ["↑ ↓", "Walk the devices on the map"],
              ["Esc", "Close a panel"],
            ].map(([k, what]) => (
              <div key={k} className="flex items-center gap-3 border-b border-line px-4 py-2.5 text-[12.5px] text-dim odd:border-r [&:nth-last-child(-n+2)]:border-b-0">
                <span className="flex gap-1">
                  {k.split(" ").map((x) => (
                    <Kbd key={x}>{x}</Kbd>
                  ))}
                </span>
                <span className="truncate">{what}</span>
              </div>
            ))}
          </Card>
        </Section>

        <Section title="About">
          <Card>
            <Row icon={<Icon.Mark size={16} />} value={`makima ${status.version}`} caption={`App ${env.app_version} · interface ${status.node.interface}`} />
            {env.cli && <Row icon={<Icon.Terminal />} value={env.cli} caption="The command this app runs" mono />}
          </Card>
        </Section>

        <div className="flex items-center justify-between gap-4 rounded-xl border border-red/25 px-4 py-3">
          <div>
            <div className="text-[13.5px] font-medium">Disconnect this device</div>
            <div className="mt-0.5 text-[12px] text-dim">It leaves the tunnel until you connect again; the network keeps its place.</div>
          </div>
          <Button variant="danger" busy={busy} icon={<Icon.Power size={14} />} onClick={() => act({ kind: "down" })}>
            Disconnect
          </Button>
        </div>
      </div>
    </div>
  );
}

/// Start at login. Switched on the first time a network is started or joined
/// from this window (see App.tsx), and the person's to switch off from then on.
function LoginItem() {
  const [on, setOn] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!inTauri) {
      setOn(false);
      return;
    }
    import("@tauri-apps/plugin-autostart")
      .then((a) => a.isEnabled())
      .then(setOn)
      .catch((e) => setError(String(e)));
  }, []);

  async function change(next: boolean) {
    setError(null);
    if (!inTauri) {
      setOn(next);
      return;
    }
    try {
      const a = await import("@tauri-apps/plugin-autostart");
      if (next) await a.enable();
      else await a.disable();
      setOn(await a.isEnabled());
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <Row
      icon={<Icon.Power />}
      value="Open at login"
      caption={error ?? "Start in the menu bar when you log in"}
      right={<Toggle on={!!on} disabled={on === null} onChange={change} label="Open at login" />}
    />
  );
}

/// The doctor's checks, on demand.
///
/// Not shown until asked for: a permanent list of green ticks is noise, and
/// the one time it matters is the time something is wrong.
function Diagnostics() {
  const [checks, setChecks] = useState<Check[] | null>(null);
  const [running, setRunning] = useState(false);

  async function run() {
    setRunning(true);
    try {
      setChecks((await api.doctor()).checks);
    } catch (e) {
      setChecks([{ name: "Diagnostics", ok: false, detail: String(e) }]);
    } finally {
      setRunning(false);
    }
  }

  const bad = checks?.filter((c) => !c.ok) ?? [];
  const good = checks?.filter((c) => c.ok) ?? [];

  return (
    <Section
      title="Diagnostics"
      right={
        <Button size="sm" onClick={run} busy={running} icon={<Icon.Pulse size={13} />}>
          {checks ? "Check again" : "Run checks"}
        </Button>
      }
    >
      <Card>
        {!checks ? (
          <p className="px-4 py-3.5 text-[13px] text-dim">The long answer to “why isn't this working?” — the tunnel, the network, the relay, each device, and names.</p>
        ) : (
          <>
            {bad.map((c) => (
              <div key={c.name} className="border-b border-line px-4 py-3 last:border-0">
                <div className="flex items-center gap-2 text-[13.5px] font-medium">
                  <Dot tone={c.warning ? "amber" : "red"} />
                  {c.name}
                </div>
                <p className="selectable mt-0.5 pl-4 text-[12.5px] leading-relaxed text-dim">{c.detail}</p>
                {c.fix && (
                  <div className="mt-2 pl-4">
                    <Code>{c.fix}</Code>
                  </div>
                )}
              </div>
            ))}
            {good.length > 0 && (
              <p className="flex items-center gap-2 px-4 py-3 text-[12.5px] text-dim">
                <Icon.Check size={14} className="text-green" />
                {bad.length === 0 ? `All ${good.length} checks passed.` : `${good.length} other check${good.length === 1 ? "" : "s"} passed: ${good.map((c) => c.name).join(", ")}.`}
              </p>
            )}
          </>
        )}
      </Card>
    </Section>
  );
}
