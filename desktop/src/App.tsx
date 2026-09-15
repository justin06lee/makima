import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, inTauri, type Action, type Environment, type Snapshot, type Status, type Tailscale } from "./api";
import { Button, Empty, IconButton, Notice, Toggle } from "./ui";
import { Icon } from "./icons";
import { Setup } from "./Setup";
import { Devices } from "./Devices";
import { ExitNodes } from "./ExitNodes";
import { Settings } from "./Settings";
import { AddDevice } from "./AddDevice";
import { Migrate, TailscaleOffer } from "./Migrate";

/// Where "not now" on the Tailscale offer is remembered.
const OFFER_DISMISSED = "makima:tailscale-offer-dismissed";

/// How often the window refreshes while it is open.
///
/// Two seconds. Paths change on their own — a relayed peer upgrades to direct
/// without anybody asking — and a window showing a stale path is worse than
/// one that flickers, because the whole reason to look is to find out what is
/// happening now.
const POLL = 2000;

export type Page = "devices" | "exit" | "settings";

/// Run a privileged action. Resolves to the CLI's output on success, or null
/// when it failed or the person said no at the prompt.
export type Act = (action: Action) => Promise<string | null>;

export default function App() {
  const [env, setEnv] = useState<Environment | null>(null);
  const [snap, setSnap] = useState<Snapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [page, setPage] = useState<Page>("devices");
  const [adding, setAdding] = useState(false);
  const [tailscale, setTailscale] = useState<Tailscale | null>(null);
  const [migrating, setMigrating] = useState(false);
  const [offerDismissed, setOfferDismissed] = useState(() => localStorage.getItem(OFFER_DISMISSED) === "1");

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

  if (!env || !snap) return <Splash />;

  const running = snap.running && !!snap.status;
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
    );
  }

  return (
    <div className="flex h-full flex-col">
      <TitleBar
        status={snap.status}
        running={running}
        busy={busy}
        act={act}
        page={page}
        setPage={setPage}
        onAdd={() => setAdding(true)}
        mac={mac}
      />

      {notice && <Notice text={notice} onDismiss={() => setNotice(null)} />}
      {offer && !offerDismissed && (
        <TailscaleOffer
          compact
          peers={offer.peers}
          onMove={() => setMigrating(true)}
          onDismiss={() => {
            localStorage.setItem(OFFER_DISMISSED, "1");
            setOfferDismissed(true);
          }}
        />
      )}

      <div className="flex min-h-0 flex-1">
        <Sidebar page={page} setPage={setPage} />
        <main className="flex min-w-0 flex-1">
          {!running || !snap.status ? (
            <Off snap={snap} busy={busy} act={act} />
          ) : page === "devices" ? (
            <Devices status={snap.status} env={env} busy={busy} act={act} onAdd={() => setAdding(true)} />
          ) : page === "exit" ? (
            <ExitNodes status={snap.status} busy={busy} act={act} />
          ) : (
            <Settings status={snap.status} env={env} busy={busy} act={act} tailscale={tailscale} onMigrate={() => setMigrating(true)} />
          )}
        </main>
      </div>

      {adding && snap.status && (
        <AddDevice status={snap.status} env={env} act={act} onClose={() => setAdding(false)} />
      )}
    </div>
  );
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
      <Icon.Mark size={28} className="pulse text-dimmer" />
    </div>
  );
}

/// The strip under the traffic lights: the switch, what this machine is
/// called, and the two things somebody opens the window to do.
function TitleBar({
  status,
  running,
  busy,
  act,
  page,
  setPage,
  onAdd,
  mac,
}: {
  status?: Status;
  running: boolean;
  busy: boolean;
  act: Act;
  page: Page;
  setPage: (p: Page) => void;
  onAdd: () => void;
  mac: boolean;
}) {
  const online = status?.peers.filter((p) => p.online).length ?? 0;
  const total = status?.peers.length ?? 0;
  const sub = !running
    ? "Not connected"
    : total === 0
      ? "Connected · no other devices yet"
      : `Connected · ${online} of ${total} device${total === 1 ? "" : "s"} online`;

  return (
    <header
      data-tauri-drag-region
      className={`flex h-[52px] shrink-0 items-center gap-3 border-b border-line bg-bg pr-3 ${mac ? "pl-[84px]" : "pl-4"}`}
    >
      <Toggle
        on={running}
        busy={busy}
        size="lg"
        label={running ? "Disconnect" : "Connect"}
        onChange={(next) => act({ kind: next ? "up" : "down" })}
      />
      <div className="min-w-0 flex-1" data-tauri-drag-region>
        <div className="truncate text-[14px] font-semibold leading-tight" data-tauri-drag-region>
          {status?.node.name ?? "makima"}
        </div>
        <div className="truncate text-[12px] leading-tight text-dim" data-tauri-drag-region>
          {sub}
        </div>
      </div>
      <Button icon={<Icon.Plus />} onClick={onAdd} disabled={!running} title="Add another device to this network">
        Add device
      </Button>
      <IconButton title="Settings" active={page === "settings"} onClick={() => setPage(page === "settings" ? "devices" : "settings")}>
        <Icon.Gear />
      </IconButton>
    </header>
  );
}

function Sidebar({ page, setPage }: { page: Page; setPage: (p: Page) => void }) {
  const items: { id: Page; label: string; icon: React.ReactNode }[] = [
    { id: "devices", label: "Devices", icon: <Icon.Devices /> },
    { id: "exit", label: "Exit nodes", icon: <Icon.Exit /> },
    { id: "settings", label: "Settings", icon: <Icon.Gear /> },
  ];
  return (
    <nav className="w-[168px] shrink-0 space-y-0.5 border-r border-line bg-sidebar p-2.5">
      {items.map((it) => (
        <button
          key={it.id}
          type="button"
          onClick={() => setPage(it.id)}
          className={`flex w-full items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-left text-[13px] font-medium transition
            ${page === it.id ? "bg-card-2 text-ink" : "text-dim hover:bg-card hover:text-ink"}`}
        >
          <span className={page === it.id ? "text-accent" : "text-dim"}>{it.icon}</span>
          {it.label}
        </button>
      ))}
    </nav>
  );
}

/// This machine is on a network, and the tunnel is down. The most common
/// state a desktop app finds, and not an error — it is what the switch fixes.
function Off({ snap, busy, act }: { snap: Snapshot; busy: boolean; act: Act }) {
  const permission = snap.error?.includes("not readable");
  return (
    <div className="flex-1">
      <Empty title={permission ? "makima is running for another account" : "makima is off"}>
        {permission ? (
          <p>
            The daemon is up, but its socket belongs to whoever started it. Connect again from this account to
            take it over.
          </p>
        ) : (
          <p>Your other devices are unreachable until you connect. Once connected, this device stays on the network — after a restart too — until you disconnect.</p>
        )}
        <div className="mt-4">
          <Button variant="primary" size="lg" busy={busy} onClick={() => act({ kind: "up" })}>
            Connect
          </Button>
        </div>
        {snap.error && !permission && !snap.error.includes("not running") && (
          <p className="selectable mt-4 font-mono text-[11px] text-dimmer">{snap.error}</p>
        )}
      </Empty>
    </div>
  );
}
