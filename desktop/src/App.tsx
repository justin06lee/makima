import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, inTauri, type Action, type Environment, type Snapshot, type Status, type Tailscale } from "./api";
import { Button, Kbd, Notice, Segmented, Toggle } from "./ui";
import { Icon } from "./icons";
import { Iris } from "./Iris";
import { Setup } from "./Setup";
import { Mesh } from "./Mesh";
import { Services } from "./Services";
import { ExitNodes } from "./ExitNodes";
import { Settings } from "./Settings";
import { AddDevice } from "./AddDevice";
import { Migrate, TailscaleOffer } from "./Migrate";
import { Palette } from "./Palette";
import { useSSH } from "./Terminal";
import { Toaster, useToast } from "./toast";

/// Where "not now" on the Tailscale offer is remembered.
const OFFER_DISMISSED = "makima:tailscale-offer-dismissed";

/// How often the window refreshes while it is open.
///
/// Two seconds. Paths change on their own — a relayed peer upgrades to direct
/// without anybody asking — and a window showing a stale path is worse than
/// one that flickers, because the whole reason to look is to find out what is
/// happening now.
const POLL = 2000;

const preview = new URLSearchParams(typeof window === "undefined" ? "" : window.location.search);

/// How many latency samples each device keeps: a minute and a half of them.
const HISTORY = 45;

export type Page = "mesh" | "services" | "exit" | "settings";

/// Run a privileged action. Resolves to the CLI's output on success, or null
/// when it failed or the person said no at the prompt.
export type Act = (action: Action) => Promise<string | null>;

/// Recent latency per device, in nanoseconds, oldest first.
export type History = Record<string, number[]>;

export default function App() {
  return (
    <Toaster>
      <Shell />
    </Toaster>
  );
}

function Shell() {
  const [env, setEnv] = useState<Environment | null>(null);
  const [snap, setSnap] = useState<Snapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  // The browser preview can open on any page and device: ?page=services&select=tenet.
  const [page, setPage] = useState<Page>(() => (!inTauri && (preview.get("page") as Page)) || "mesh");
  const [selected, setSelected] = useState<string | null>(() => (!inTauri && preview.get("select")) || null);
  const [adding, setAdding] = useState(false);
  const [palette, setPalette] = useState(false);
  const [tailscale, setTailscale] = useState<Tailscale | null>(null);
  const [migrating, setMigrating] = useState(false);
  const [offerDismissed, setOfferDismissed] = useState(() => localStorage.getItem(OFFER_DISMISSED) === "1");
  const [history, setHistory] = useState<History>({});
  const toast = useToast();
  const { ssh, picker, error: sshError } = useSSH();

  useEffect(() => {
    if (sshError) toast(sshError, "error");
  }, [sshError, toast]);

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
      if (s.status) {
        const peers = s.status.peers;
        setHistory((h) => {
          const next: History = {};
          for (const p of peers) next[p.name] = [...(h[p.name] ?? []), p.online ? p.latency : 0].slice(-HISTORY);
          return next;
        });
      }
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
          setPage("mesh");
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

  const running = !!snap?.running && !!snap.status;

  // The keys a person reaches for without looking.
  const keys = useRef({ running, adding, palette, migrating });
  keys.current = { running, adding, palette, migrating };
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const k = keys.current;
      if (k.migrating || !(e.metaKey || e.ctrlKey)) return;
      if (e.key === "k") {
        e.preventDefault();
        setPalette((p) => !p);
      } else if (e.key === "n" && k.running && !k.adding) {
        e.preventDefault();
        setPalette(false);
        setAdding(true);
      } else if (e.key === "," ) {
        e.preventDefault();
        setPage("settings");
      } else if (["1", "2", "3", "4"].includes(e.key)) {
        e.preventDefault();
        setPage((["mesh", "services", "exit", "settings"] as Page[])[Number(e.key) - 1]);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

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

  const status = snap.status;

  return (
    <div className="flex h-full flex-col bg-bg">
      <TitleBar
        status={status}
        running={running}
        busy={busy}
        act={act}
        page={page}
        setPage={setPage}
        onAdd={() => setAdding(true)}
        onSearch={() => setPalette(true)}
        mac={mac}
      />

      {notice && <Notice text={notice} onDismiss={() => setNotice(null)} />}
      {running && offer && !offerDismissed && (
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

      <main className="relative flex min-h-0 flex-1">
        {!running || !status ? (
          <Off snap={snap} busy={busy} act={act} />
        ) : page === "mesh" ? (
          <Mesh
            status={status}
            env={env}
            busy={busy}
            act={act}
            history={history}
            selected={selected}
            setSelected={setSelected}
            onAdd={() => setAdding(true)}
            ssh={ssh}
            goto={setPage}
          />
        ) : page === "services" ? (
          <Services status={status} busy={busy} act={act} />
        ) : page === "exit" ? (
          <ExitNodes status={status} busy={busy} act={act} />
        ) : (
          <Settings status={status} env={env} busy={busy} act={act} tailscale={tailscale} onMigrate={() => setMigrating(true)} />
        )}
      </main>

      {picker}

      {adding && status && <AddDevice status={status} env={env} act={act} onClose={() => setAdding(false)} />}

      {palette && (
        <Palette
          status={status}
          running={running}
          onClose={() => setPalette(false)}
          goto={(p) => setPage(p)}
          select={(name) => {
            setPage("mesh");
            setSelected(name);
          }}
          ssh={ssh}
          act={act}
          onAdd={() => setAdding(true)}
        />
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
    <div className="grain flex h-full items-center justify-center bg-bg" data-tauri-drag-region>
      <Iris size={56} state="busy" className="opacity-60" />
    </div>
  );
}

/// The strip under the traffic lights: this device and its switch on the
/// left, the pages in the middle, and the two things somebody opens the
/// window to do on the right.
function TitleBar({
  status,
  running,
  busy,
  act,
  page,
  setPage,
  onAdd,
  onSearch,
  mac,
}: {
  status?: Status;
  running: boolean;
  busy: boolean;
  act: Act;
  page: Page;
  setPage: (p: Page) => void;
  onAdd: () => void;
  onSearch: () => void;
  mac: boolean;
}) {
  const online = status?.peers.filter((p) => p.online).length ?? 0;
  const total = status?.peers.length ?? 0;
  const sub = busy
    ? running
      ? "Working…"
      : "Connecting…"
    : !running
      ? "Not connected"
      : total === 0
        ? "Connected · no other devices yet"
        : `${online} of ${total} device${total === 1 ? "" : "s"} reachable`;

  return (
    <header
      data-tauri-drag-region
      className={`flex h-[52px] shrink-0 items-center gap-3 border-b border-line bg-panel/70 pr-3 ${mac ? "pl-[84px]" : "pl-4"}`}
    >
      <div className="flex min-w-0 items-center gap-2.5" data-tauri-drag-region>
        <Iris size={22} state={busy ? "busy" : running ? "on" : "off"} />
        <div className="min-w-0 max-w-[170px]" data-tauri-drag-region>
          <div className="display truncate text-[14px] leading-tight" data-tauri-drag-region>
            {status?.node.name ?? "makima"}
          </div>
          <div className="tabular truncate text-[11.5px] leading-tight text-dim" data-tauri-drag-region>
            {sub}
          </div>
        </div>
        <Toggle
          on={running}
          busy={busy}
          label={running ? "Disconnect this device" : "Connect this device"}
          onChange={(next) => act({ kind: next ? "up" : "down" })}
        />
      </div>

      <div className="flex min-w-0 flex-1 justify-center" data-tauri-drag-region>
        <Segmented
          value={page === "settings" ? ("" as Page) : page}
          onChange={setPage}
          options={[
            { value: "mesh", label: <><Icon.Mesh size={14} />Mesh</>, title: "Your devices (⌘1)" },
            { value: "services", label: <><Icon.Services size={14} />Services</>, title: "What they offer (⌘2)" },
            { value: "exit", label: <><Icon.Exit size={14} />Exit node</>, title: "Route this device's traffic (⌘3)" },
          ]}
        />
      </div>

      <div className="flex items-center gap-1">
        <button
          type="button"
          onClick={onSearch}
          title="Search devices, services and actions"
          className="flex h-[30px] items-center gap-2 rounded-lg px-2 text-dim transition hover:bg-ink/6 hover:text-ink"
        >
          <Icon.Search size={15} />
          <Kbd>⌘K</Kbd>
        </button>
        <button
          type="button"
          onClick={() => setPage(page === "settings" ? "mesh" : "settings")}
          title="Settings (⌘,)"
          aria-label="Settings"
          className={`flex size-[30px] items-center justify-center rounded-lg transition hover:bg-ink/6 ${page === "settings" ? "bg-ink/8 text-ink" : "text-dim hover:text-ink"}`}
        >
          <Icon.Gear size={16} />
        </button>
        <Button variant="primary" size="sm" icon={<Icon.Plus size={14} />} onClick={onAdd} disabled={!running} title="Add another device to this network (⌘N)" className="ml-1">
          Add device
        </Button>
      </div>
    </header>
  );
}

/// This machine is on a network, and the tunnel is down. The most common
/// state a desktop app finds, and not an error — it is what the switch fixes.
function Off({ snap, busy, act }: { snap: Snapshot; busy: boolean; act: Act }) {
  const permission = snap.error?.includes("not readable");
  return (
    <div className="grain flex flex-1 flex-col items-center justify-center px-8 text-center">
      <div className="relative">
        <Iris size={132} state={busy ? "busy" : "off"} />
      </div>
      <h1 className="display mt-7 text-[26px]">{permission ? "makima is running for another account" : "makima is off"}</h1>
      <p className="mt-2 max-w-[400px] text-[13.5px] leading-relaxed text-dim">
        {permission
          ? "The daemon is up, but its socket belongs to whoever started it. Connect again from this account to take it over."
          : "Your other devices are out of reach until you connect. Once connected, this device stays on the network — after a restart too — until you switch it off."}
      </p>
      <div className="mt-6">
        <Button variant="primary" size="lg" busy={busy} icon={<Icon.Power size={16} />} onClick={() => act({ kind: "up" })}>
          Connect
        </Button>
      </div>
      {snap.error && !permission && !snap.error.includes("not running") && (
        <p className="selectable mt-5 max-w-md font-mono text-[11px] text-dimmer">{snap.error}</p>
      )}
    </div>
  );
}
