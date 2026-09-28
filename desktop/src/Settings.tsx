import { useEffect, useState } from "react";
import { api, inTauri, type Check, type Environment, type Status, type Tailscale } from "./api";
import type { Act } from "./App";
import { Button, Card, Code, Dot, PageHeader, Row, Section, Toggle } from "./ui";
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
    <div className="flex min-h-0 flex-1 flex-col">
      <PageHeader title="Settings" />
      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[560px] space-y-8 px-6 pb-10 pt-6">
          <Section title="App">
            <Card>
              <LoginItem />
              <TerminalSetting />
              <Row
                value="Command line"
                caption={env.linked ? "makima is on your PATH at /usr/local/bin/makima" : "Use makima from your terminal too"}
                right={
                  env.linked ? (
                    <span className="flex items-center gap-1.5 text-[12px] text-dim">
                      <Icon.Check size={14} className="text-green" /> Installed
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
                value={env.holds_mesh ? "This device holds the network" : status.serverless ? "No server — devices are paired directly" : status.server ?? "Static network"}
                caption={
                  env.holds_mesh
                    ? "Invites are made here. Keep it on, so others can join and find each other."
                    : status.serverless
                      ? "Add devices with makima pair"
                      : "The device that holds the network"
                }
                mono={!env.holds_mesh && !status.serverless && !!status.server}
              />
              {status.relay.url && (
                <Row
                  value={status.relay.url}
                  caption={
                    <span className="flex items-center gap-1.5">
                      <Dot tone={status.relay.connected ? "green" : "grey"} size="sm" />
                      {status.relay.connected ? "Relay connected — used when a direct path can't be found" : "Relay not connected"}
                    </span>
                  }
                  mono
                />
              )}
              <Row
                value={status.dns_active && status.domain ? `*.${status.domain}` : "Names off"}
                caption={status.dns_active ? "Every device answers to its name" : "Reach devices by address"}
                mono={status.dns_active}
              />
              {status.firewall?.backend && status.firewall.backend !== "none" && status.firewall.backend !== "unsupported" && (
                <Row
                  value={`Firewall: ${status.firewall.backend === "macos" ? "macOS" : status.firewall.backend}`}
                  caption={status.firewall.trusted ? "Tunnel traffic is allowed through" : status.firewall.detail ?? "Tunnel traffic may be blocked"}
                />
              )}
            </Card>
          </Section>

          {tailscale?.installed && (
            <Section title="Tailscale">
              <Card>
                <Row
                  value={tailscale.running ? `Running, with ${tailscale.peers} other device${tailscale.peers === 1 ? "" : "s"}` : "Installed, not connected"}
                  caption={tailscale.running ? "Move every device to makima through it, then take it off each one" : "Connect Tailscale to move your devices through it"}
                  right={
                    <Button size="sm" disabled={!tailscale.running} onClick={onMigrate}>
                      Move to makima…
                    </Button>
                  }
                />
              </Card>
            </Section>
          )}

          <Diagnostics />

          <Section title="About">
            <Card>
              <Row value={`makima ${status.version}`} caption={`App ${env.app_version} · interface ${status.node.interface}`} />
              {env.cli && <Row value={env.cli} caption="The command this app runs" mono />}
            </Card>
          </Section>

          <div className="flex items-center justify-between gap-4 rounded-xl border border-line px-4 py-3">
            <div className="min-w-0">
              <div className="text-[13px]">Disconnect this device</div>
              <div className="mt-px text-[12px] text-dim">It stays on the network and reconnects when you turn it back on.</div>
            </div>
            <Button variant="danger" size="sm" busy={busy} onClick={() => act({ kind: "down" })}>
              Disconnect
            </Button>
          </div>
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
      value="Open at login"
      caption={error ?? "Keep makima in the menu bar from the moment you log in"}
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

  return (
    <Section
      title="Diagnostics"
      right={
        <Button size="sm" onClick={run} busy={running} icon={checks ? <Icon.Refresh size={13} /> : undefined}>
          {checks ? "Check again" : "Run checks"}
        </Button>
      }
    >
      <Card>
        {!checks ? (
          <p className="px-4 py-4 text-[12.5px] text-dim">The long answer to “why isn't this working?”</p>
        ) : bad.length === 0 ? (
          <p className="flex items-center gap-2.5 px-4 py-4 text-[12.5px] text-dim">
            <Dot tone="green" />
            All {checks.length} checks passed.
          </p>
        ) : (
          <>
            {bad.map((c) => (
              <div key={c.name} className="border-b border-line px-4 py-3 last:border-0">
                <div className="flex items-center gap-2.5 text-[13px] font-medium">
                  <Dot tone={c.warning ? "amber" : "red"} />
                  {c.name}
                </div>
                <p className="mt-0.5 pl-[17px] text-[12px] leading-relaxed text-dim">{c.detail}</p>
                {c.fix && (
                  <div className="mt-2 pl-[17px]">
                    <Code>{c.fix}</Code>
                  </div>
                )}
              </div>
            ))}
            <p className="flex items-center gap-2.5 bg-sunken/50 px-4 py-2.5 text-[12px] text-dim">
              <Dot tone="green" size="sm" />
              {checks.length - bad.length} other check{checks.length - bad.length === 1 ? "" : "s"} passed
            </p>
          </>
        )}
      </Card>
    </Section>
  );
}
