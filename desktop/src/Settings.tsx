import { useEffect, useState } from "react";
import { api, inTauri, type Check, type Environment, type Status, type Tailscale } from "./api";
import type { Act } from "./App";
import { Button, Card, Code, Dot, Row, Section, Toggle } from "./ui";

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
    <div className="fade-in mx-auto w-full max-w-[560px] space-y-6 px-6 pb-8 pt-5">
      <h1 className="text-[22px] font-semibold tracking-tight">Settings</h1>

      <Section title="General">
        <Card>
          <LoginItem />
          <Row
            value="Command line"
            caption={env.linked ? "makima is on PATH at /usr/local/bin/makima" : "makima is not on PATH for your terminal yet"}
            right={
              env.linked ? (
                <span className="text-[12px] text-dim">Installed</span>
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
            caption={env.holds_mesh ? "Invites are created here. It runs whenever this device is on, so others can join or leave." : status.serverless ? "Add devices with makima pair" : "The device that started the network"}
          />
          {status.relay.url && (
            <Row value={status.relay.url} caption={status.relay.connected ? "Relay, connected — used when a direct path cannot be found" : "Relay, not connected"} mono />
          )}
          <Row
            value={status.dns_active && status.domain ? `*.${status.domain}` : "Names off"}
            caption={status.dns_active ? "Every device answers to its name" : "Reach devices by address"}
            mono={status.dns_active}
          />
          {status.firewall?.backend && status.firewall.backend !== "none" && (
            <Row
              value={`Firewall: ${status.firewall.backend}`}
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
              caption={
                tailscale.running
                  ? "Move every device to makima through it, then take it off each one"
                  : "Connect Tailscale to move your devices through it"
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

      <Section title="About">
        <Card>
          <Row value={`makima ${status.version}`} caption={`App ${env.app_version} · interface ${status.node.interface}`} />
          {env.cli && <Row value={env.cli} caption="The command this app runs" mono />}
        </Card>
      </Section>

      <div className="flex justify-end">
        <Button variant="danger" busy={busy} onClick={() => act({ kind: "down" })}>
          Disconnect
        </Button>
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

  return (
    <Section
      title="Diagnostics"
      right={
        <Button size="sm" onClick={run} busy={running}>
          {checks ? "Check again" : "Run checks"}
        </Button>
      }
    >
      <Card>
        {!checks ? (
          <p className="px-4 py-3.5 text-[13px] text-dim">The long-form answer to “why is this not working”.</p>
        ) : bad.length === 0 ? (
          <p className="flex items-center gap-2 px-4 py-3.5 text-[13px] text-dim">
            <Dot tone="green" />
            All {checks.length} checks passed.
          </p>
        ) : (
          bad.map((c) => (
            <div key={c.name} className="border-b border-line px-4 py-3 last:border-0">
              <div className="flex items-center gap-2 text-[13.5px] font-medium">
                <Dot tone={c.warning ? "amber" : "red"} />
                {c.name}
              </div>
              <p className="mt-0.5 pl-4 text-[12.5px] leading-relaxed text-dim">{c.detail}</p>
              {c.fix && (
                <div className="mt-1.5 pl-4">
                  <Code>{c.fix}</Code>
                </div>
              )}
            </div>
          ))
        )}
      </Card>
    </Section>
  );
}
