import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, inTauri, type Action, type Environment, type Snapshot, type Status, type Tailscale } from "./api";
import { Button, Copyable, Dot, Kbd, Notice, Toaster, Toggle, toast } from "./ui";
import { Icon } from "./icons";
import { Setup } from "./Setup";
import { Devices } from "./Devices";
import { Services } from "./Services";
import { ExitNodes } from "./ExitNodes";
import { Settings } from "./Settings";
import { AddDevice } from "./AddDevice";
import { Migrate } from "./Migrate";
import { Palette } from "./Palette";
import { useSSH } from "./Terminal";

/// Where "not now" on the Tailscale offer is remembered.
const OFFER_DISMISSED = "makima:tailscale-offer-dismissed";

/// How often the window refreshes while it is open.
///
/// Two seconds. Paths change on their own — a relayed peer upgrades to direct
/// without anybody asking — and a window showing a stale path is worse than
/// one that flickers, because the whole reason to look is to find out what is
/// happening now.
const POLL = 2000;

export type Page = "devices" | "services" | "exit" | "settings";

/// Run a privileged action. Resolves to the CLI's output on success, or null
/// when it failed or the person said no at the prompt.
export type Act = (action: Action) => Promise<string | null>;

/// What a screen needs to send the window somewhere else.
export type Nav = {
  page: (p: Page) => void;
  device: (name: string | null) => void;
  add: () => void;
  ssh: (peer: string) => void;
};

const PAGES: { id: Page; label: string; icon: (p: { size?: number }) => React.ReactNode; key: string }[] = [
  { id: "devices", label: "Devices", icon: Icon.Devices, key: "1" },
  { id: "services", label: "Services", icon: Icon.Services, key: "2" },
  { id: "exit", label: "Exit node", icon: Icon.Exit, key: "3" },
  { id: "settings", label: "Settings", icon: Icon.Gear, key: "," },
];

export default function App() {
  const [env, setEnv] = useState<Environment | null>(null);
  const [snap, setSnap] = useState<Snapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [page, setPage] = useState<Page>("devices");
  const [selected, setSelected] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [palette, setPalette] = useState(false);
  const [tailscale, setTailscale] = useState<Tailscale | null>(null);
  const [migrating, setMigrating] = useState(false);
  const [offerDismissed, setOfferDismissed] = useState(() => localStorage.getItem(OFFER_DISMISSED) === "1");
  const { ssh, picker } = useSSH();

  // Tailscale is looked for once, when the window opens, and again after a
  // move — it is the one thing that changes it.
  useEffect(() => {
    if (!migrating) api.migrate.detect().then(setTailscale).catch(() => setTailscale(null));
  }, [migrating]);

  const refresh = useCallback(async () => {
    try {
      const [e, s] = await Promise.all([api.environment(), api.status()]);
      setEnv(e);
      setSnap(s);
    } catch (e) {
      setSnap({ running: false, error: String(e) });
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, POLL);
    return () => clearInterval(t);
  }, [refresh]);

  // The menu bar can ask the window to do two things: open the add-device
  // flow, and show an error it has nowhere to put itself.
  useEffect(() => {
    if (!inTauri) return;
    const subs = [
      listen<string>("navigate", (e) => {
        if (e.payload === "add-device") {
          setPage("devices");
          setAdding(true);
        }
      }),
      listen<string>("notice", (e) => setNotice(e.payload)),
    ];
    return () => {
      subs.forEach((p) => p.then((un) => un()));
    };
  }, []);

  const act: Act = useCallback(
    async (action) => {
      setBusy(true);
      setNotice(null);
      try {
        const out = await api.act(action);
        if (!out.ok) {
          // "cancelled" is the user saying no at the auth prompt. That is an
          // answer, not a failure, and it should not look like one.
          if (out.output !== "cancelled") setNotice(out.output);
          return null;
        }
        if (action.kind === "up" || action.kind === "join") void openAtLoginOnce();
        const said = confirmation(action);
        if (said) toast(said);
        await refresh();
        return out.output ?? "";
      } catch (e) {
        setNotice(String(e));
        return null;
      } finally {
        setBusy(false);
      }
    },
    [refresh],
  );

  const running = !!snap?.running && !!snap.status;
  const onNetwork = running || !!env?.member;

  const nav: Nav = {
    page: (p) => {
      setPage(p);
      if (p !== "devices") setSelected(null);
    },
    device: (name) => {
      setPage("devices");
      setSelected(name);
    },
    add: () => running && setAdding(true),
    ssh,
  };

  // The keyboard: ⌘K for everything, ⌘1–3 and ⌘, for the pages, ⌘N to add a
  // device. Only once there is a network to move around in.
  useEffect(() => {
    if (!onNetwork || migrating) return;
    const onKey = (e: KeyboardEvent) => {
      if (!(e.metaKey || e.ctrlKey) || e.altKey) return;
      const k = e.key.toLowerCase();
      if (k === "k") {
        e.preventDefault();
        setPalette((p) => !p);
        return;
      }
      if (adding || palette) return;
      const to = PAGES.find((p) => p.key === k);
      if (to && running) {
        e.preventDefault();
        setPage(to.id);
        if (to.id !== "devices") setSelected(null);
      } else if (k === "n" && running) {
        e.preventDefault();
        setAdding(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onNetwork, migrating, adding, palette, running]);

  if (!env || !snap) return <Splash />;

  const mac = env.platform === "macos";
  const offer = tailscale?.running && tailscale.peers > 0 ? tailscale : null;

  if (migrating) {
    return (
      <Migrate
        mac={mac}
        onClose={() => {
          setMigrating(false);
          void refresh();
        }}
      />
    );
  }

  if (!running && !env.member) {
    return (
      <>
        <Setup
          env={env}
          busy={busy}
          act={act}
          notice={notice}
          dismiss={() => setNotice(null)}
          mac={mac}
          tailscale={offer}
          onMigrate={() => setMigrating(true)}
        />
        <Toaster />
      </>
    );
  }

  const status = snap.status;

  return (
    <div className="flex h-full">
      <Sidebar
        status={status}
        env={env}
        running={running}
        busy={busy}
        act={act}
        page={page}
        nav={nav}
        mac={mac}
        onPalette={() => setPalette(true)}
        offer={offer && !offerDismissed ? offer : null}
        onMigrate={() => setMigrating(true)}
        onDismissOffer={() => {
          localStorage.setItem(OFFER_DISMISSED, "1");
          setOfferDismissed(true);
        }}
      />

      <main className="my-2 mr-2 flex min-w-0 flex-1 flex-col overflow-hidden rounded-xl bg-panel shadow-[var(--panel-shadow)]">
        {notice && <Notice text={notice} onDismiss={() => setNotice(null)} />}
        {!running || !status ? (
          <Off snap={snap} busy={busy} act={act} />
        ) : page === "devices" ? (
          <Devices status={status} env={env} busy={busy} act={act} nav={nav} selected={selected} />
        ) : page === "services" ? (
          <Services status={status} busy={busy} act={act} nav={nav} />
        ) : page === "exit" ? (
          <ExitNodes status={status} busy={busy} act={act} />
        ) : (
          <Settings status={status} env={env} busy={busy} act={act} tailscale={tailscale} onMigrate={() => setMigrating(true)} />
        )}
      </main>

      {adding && status && <AddDevice status={status} env={env} act={act} onClose={() => setAdding(false)} />}
      {palette && (
        <Palette
          status={status}
          running={running}
          nav={nav}
          act={act}
          onClose={() => setPalette(false)}
        />
      )}
      {picker}
      <Toaster />
    </div>
  );
}

/// What the toast says once an action has gone through. Nothing for the ones
/// whose result is already on the screen in front of you.
function confirmation(a: Action): string | null {
  switch (a.kind) {
    case "up":
      return "Connected";
    case "down":
      return "Disconnected";
    case "exit-node":
      return a.name ? `Internet traffic now goes through ${a.name}` : "Using this device's own connection";
    case "advertise-exit":
      return a.on ? "Offered as an exit node" : "No longer offered as an exit node";
    case "allow":
      return `Port ${a.port} is shared`;
    case "deny":
      return `Port ${a.port} is no longer shared`;
    case "link-cli":
      return "makima is on your PATH";
    default:
      return null;
  }
}

/// The first time a network is started or joined from this window, the app
/// becomes a login item, so the menu bar has makima in it from the next login
/// on. Once: the switch in Settings is the person's from then on, and turning
/// it off has to stick. The tunnel itself does not depend on this — it is
/// registered with the system and comes back on its own — this is only the
/// menu bar coming back with it.
async function openAtLoginOnce() {
  if (!inTauri) return;
  const key = "makima:open-at-login-offered";
  if (localStorage.getItem(key)) return;
  localStorage.setItem(key, "1");
  try {
    const a = await import("@tauri-apps/plugin-autostart");
    if (!(await a.isEnabled())) await a.enable();
  } catch {
    // A login item that could not be made is not worth an error in the
    // window; Settings still has the switch.
  }
}

function Splash() {
  return (
    <div className="flex h-full items-center justify-center" data-tauri-drag-region>
      <span className="pulse text-[15px] font-semibold tracking-[-0.02em] text-dimmer">makima</span>
    </div>
  );
}

/// The column on the left: this machine and its switch, the pages, and the
/// two things somebody opens the window to do.
function Sidebar({
  status,
  env,
  running,
  busy,
  act,
  page,
  nav,
  mac,
  onPalette,
  offer,
  onMigrate,
  onDismissOffer,
}: {
  status?: Status;
  env: Environment;
  running: boolean;
  busy: boolean;
  act: Act;
  page: Page;
  nav: Nav;
  mac: boolean;
  onPalette: () => void;
  offer: Tailscale | null;
  onMigrate: () => void;
  onDismissOffer: () => void;
}) {
  const peers = status?.peers ?? [];
  const online = peers.filter((p) => p.online).length;
  const services = peers.reduce((n, p) => n + (p.online ? p.services?.length ?? 0 : 0), 0) + (status?.services?.length ?? 0);
  const meta: Record<Page, React.ReactNode> = {
    devices: running ? `${online + 1}/${peers.length + 1}` : null,
    services: running && services > 0 ? services : null,
    exit: running ? (status?.exit_node ? <span className="text-ink-2">{status.exit_node}</span> : "Off") : null,
    settings: null,
  };

  return (
    <aside className="flex w-[228px] shrink-0 flex-col" data-tauri-drag-region>
      <div className={mac ? "h-[46px] shrink-0" : "h-3 shrink-0"} data-tauri-drag-region />

      {/* This machine, and the switch. */}
      <div className="px-4 pb-4 pt-1" data-tauri-drag-region>
        <div className="flex items-center gap-3" data-tauri-drag-region>
          <div className="min-w-0 flex-1" data-tauri-drag-region>
            <div className="truncate text-[14px] font-semibold tracking-[-0.01em]" data-tauri-drag-region>
              {status?.node.name ?? "makima"}
            </div>
          </div>
          <Toggle
            on={running}
            busy={busy}
            label={running ? "Disconnect" : "Connect"}
            onChange={(next) => act({ kind: next ? "up" : "down" })}
          />
        </div>
        <div className="mt-1 flex min-w-0 items-center gap-2 text-[12px] text-dim">
          <Dot tone={running ? "green" : "grey"} size="sm" live={running} />
          <span className="shrink-0">{running ? "Connected" : "Disconnected"}</span>
          {running && status && (
            <>
              <span className="text-dimmer">·</span>
              <Copyable value={status.node.address} what="this device's address" className="!text-[11.5px] text-dim" />
            </>
          )}
        </div>
      </div>

      <div className="px-2.5">
        <button
          type="button"
          onClick={onPalette}
          className="flex h-8 w-full items-center gap-2 rounded-lg border border-line bg-panel/70 px-2.5 text-left text-[12.5px] text-dimmer shadow-[0_1px_1px_rgba(0,0,0,0.02)] transition-colors hover:border-line-2 hover:text-dim"
        >
          <Icon.Search size={14} />
          <span className="flex-1">Search or run…</span>
          <span className="flex gap-0.5">
            <Kbd>⌘</Kbd>
            <Kbd>K</Kbd>
          </span>
        </button>
      </div>

      <nav className="mt-3 space-y-px px-2.5">
        {PAGES.map((p) => {
          const on = page === p.id && running;
          const off = !running && p.id !== "settings";
          return (
            <button
              key={p.id}
              type="button"
              disabled={off || !running}
              onClick={() => nav.page(p.id)}
              className={`group flex h-8 w-full items-center gap-2.5 rounded-lg px-2.5 text-left text-[13px] transition-colors disabled:opacity-40
                ${on ? "bg-panel font-medium text-ink shadow-[var(--panel-shadow)]" : "text-ink-2 enabled:hover:bg-hover"}`}
            >
              <span className={on ? "text-ink" : "text-dim"}>{p.icon({ size: 15 })}</span>
              <span className="flex-1 truncate">{p.label}</span>
              {meta[p.id] !== null && <span className="tabular truncate text-[11.5px] font-normal text-dimmer">{meta[p.id]}</span>}
            </button>
          );
        })}
      </nav>

      <div className="flex-1" data-tauri-drag-region />

      {offer && (
        <div className="fade-in mx-2.5 mb-2.5 rounded-xl border border-line bg-panel/70 p-3">
          <div className="flex items-start gap-2">
            <p className="min-w-0 flex-1 text-[12px] leading-snug text-ink-2">
              Tailscale is running here with {offer.peers} other device{offer.peers === 1 ? "" : "s"}.
            </p>
            <button type="button" onClick={onDismissOffer} title="Not now" aria-label="Not now" className="-mr-1 -mt-0.5 text-dimmer hover:text-ink">
              <Icon.Close size={14} />
            </button>
          </div>
          <button type="button" onClick={onMigrate} className="mt-1.5 inline-flex items-center gap-1 text-[12px] font-medium text-ink hover:underline">
            Move them to makima <Icon.Arrow size={13} />
          </button>
        </div>
      )}

      <div className="space-y-2 px-2.5 pb-3">
        <Button className="w-full" variant="primary" icon={<Icon.Plus size={15} />} onClick={nav.add} disabled={!running} title="Add another device to this network (⌘N)">
          Add device
        </Button>
        <div className="flex items-center justify-between px-1.5 text-[11px] text-dimmer">
          <span className="truncate">{env.holds_mesh ? "Holds the network" : status?.serverless ? "Paired network" : status?.domain ? `.${status.domain} network` : "makima"}</span>
          <span className="tabular">{status?.version ?? env.app_version}</span>
        </div>
      </div>
    </aside>
  );
}

/// This machine is on a network, and the tunnel is down. The most common
/// state a desktop app finds, and not an error — it is what the switch fixes,
/// so the one big thing on the screen is the switch.
function Off({ snap, busy, act }: { snap: Snapshot; busy: boolean; act: Act }) {
  const permission = snap.error?.includes("not readable");
  return (
    <div className="flex flex-1 flex-col items-center justify-center px-8 text-center" data-tauri-drag-region>
      <button
        type="button"
        onClick={() => act({ kind: "up" })}
        disabled={busy}
        title="Connect"
        aria-label="Connect"
        className="group relative flex size-[88px] items-center justify-center rounded-full border border-line-2 bg-panel text-ink shadow-[0_1px_2px_rgba(0,0,0,0.05),0_12px_32px_-12px_rgba(0,0,0,0.22)] transition hover:border-dim active:scale-[0.97] disabled:opacity-70"
      >
        {busy ? <span className="spin size-7 rounded-full border-2 border-line-2 border-t-ink" /> : <Icon.Power size={30} className="transition-transform duration-200 group-hover:scale-105" />}
      </button>
      <p className="mt-6 text-[15px] font-semibold tracking-[-0.01em]">
        {busy ? "Connecting…" : permission ? "makima is running for another account" : "You're disconnected"}
      </p>
      <p className="mt-1 max-w-[340px] text-[12.5px] leading-relaxed text-dim">
        {permission
          ? "The daemon is up, but its socket belongs to whoever started it. Connect from this account to take it over."
          : "Your other devices can't be reached until you connect. Once you do, this device stays on the network — after a restart too — until you turn it off."}
      </p>
      {snap.error && !permission && !snap.error.includes("not running") && (
        <p className="selectable mt-6 max-w-[420px] font-mono text-[11px] text-dimmer">{snap.error}</p>
      )}
    </div>
  );
}
