import { invoke } from "@tauri-apps/api/core";

// The shapes the daemon actually sends, mirrored from internal/localapi.
// Written out rather than inferred so a field disappearing on the Go side is a
// type error here instead of an undefined at render time.

export type Service = { name?: string; port: number; scheme?: string };

export type Peer = {
  name: string;
  address: string;
  online: boolean;
  path: string;
  direct: boolean;
  latency: number;
  relay_url?: string;
  services?: Service[];
  routes?: string[];
  exit_node: boolean;
};

export type NodeInfo = {
  name: string;
  address: string;
  interface: string;
  services?: Service[];
  advertised_routes?: string[];
  approved_routes?: string[];
  advertises_exit: boolean;
  exit_approved: boolean;
};

/// Mirrors serve.Status, which embeds serve.Service — so name, port, target
/// and auto arrive flattened alongside the rest.
export type ServiceStatus = {
  name?: string;
  port: number;
  target: string;
  auto?: boolean;
  listening: boolean;
  address?: string;
  error?: string;
  active: number;
  total: number;
  failed: number;
  target_up: boolean;
};

export type Status = {
  version: string;
  node: NodeInfo;
  peers: Peer[];
  services?: ServiceStatus[];
  firewall?: { backend?: string; trusted?: boolean; detail?: string };
  managed: boolean;
  serverless: boolean;
  server?: string;
  relay: { url?: string; connected: boolean };
  domain?: string;
  dns_active: boolean;
  exit_node?: string;
  pairing?: { address: string; expires: string };
  inbox: { dir?: string; active: boolean; received: number };
  ssh: {
    active: boolean;
    addr?: string;
    user?: string;
    fingerprint?: string;
    keys: number;
    sources?: string[];
    key_error?: string;
  };
  filtering: boolean;
  dropped: number;
  since: string;
};

export type Snapshot = {
  running: boolean;
  error?: string;
  status?: Status;
};

/// What is true about this machine before the daemon says anything.
export type Environment = {
  cli?: string;
  member: boolean;
  holds_mesh: boolean;
  linked: boolean;
  platform: string;
  app_version: string;
};

export type Check = { name: string; ok: boolean; detail: string; fix?: string; warning?: boolean };

export type Ping = {
  name: string;
  address: string;
  direct: boolean;
  path: string;
  latency: number;
  relay_latency: number;
  relay_url?: string;
  candidates?: string[];
};

export type Outcome = { ok: boolean; output: string };

/// Every privileged operation the app can ask for. Mirrors the Rust enum, so
/// adding one means touching both sides on purpose.
export type Action =
  | { kind: "up" }
  | { kind: "join"; invite: string }
  | { kind: "down" }
  | { kind: "allow"; port: number }
  | { kind: "deny"; port: number }
  | { kind: "exit-node"; name: string }
  | { kind: "advertise-exit"; on: boolean }
  | { kind: "invite" }
  | { kind: "pair" }
  | { kind: "link-cli" };

// --- moving from Tailscale -------------------------------------------------
// Mirrors internal/migrate. The run itself is `makima migrate`, streaming one
// event per line; the app carries them here as "migrate" events.

export type Tailscale = { installed: boolean; running: boolean; tailnet?: string; self?: string; peers: number; online: number; error?: string };

export type Facts = {
  os: string;
  arch: string;
  user: string;
  sudo: "root" | "nopasswd" | "password" | "none";
  makima?: string;
  member?: boolean;
  holds?: boolean;
  via?: string;
  openssh?: boolean;
  pkg?: string;
};

export type Candidate = {
  id: string;
  name: string;
  host: string;
  dns?: string;
  os: string;
  ips: string[];
  online: boolean;
  local?: boolean;
  shared?: boolean;
  facts?: Facts;
  access?: { user?: string; auth_url?: string; error?: string };
  eligible: boolean;
  why?: string;
  needs_password?: boolean;
  public?: string;
  reach?: string;
  score: number;
  pitch?: string;
  checking?: boolean;
};

export type Plan = { tailnet: string; machines: Candidate[]; controller?: string; advice?: string; version: string };

export type Choice = {
  plan: Plan;
  controller: string;
  advertise?: string;
  selected: string[];
  passwords?: Record<string, string>;
  remove_tailscale: boolean;
};

export type MachineOutcome = { id: string; name: string; outcome: "moved" | "moved?" | "rolled_back" | "stayed"; detail?: string; notes?: string[] };
export type MigrationResult = { ok: boolean; server?: string; controller?: string; machines: MachineOutcome[]; error?: string };

export type MigrateEvent =
  | { type: "machine"; machine: string; candidate: Candidate }
  | { type: "auth"; machine: string; url: string }
  | { type: "plan"; plan: Plan }
  | { type: "error"; detail: string }
  | { type: "step"; machine: string; step: string; state: "running" | "ok" | "failed"; detail?: string }
  | { type: "prompt" }
  | { type: "result"; result: MigrationResult }
  | { type: "exit"; code?: number; detail?: string };

/// Whether this is running inside the Tauri window at all.
///
/// It is not when the interface is opened in a plain browser from `bun run
/// dev`, which is how it gets worked on: vite proxies /api to the devserver,
/// and everything the CLI would do is pretended. Nothing in that mode can
/// change a machine, because there is no machine — only a mesh being shown.
export const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

const browser = {
  /// ?state=setup|off|on decides which screen; ?holds=0 makes this a joined
  /// device rather than the one holding the network.
  params: () => new URLSearchParams(window.location.search),
  async get<T>(path: string): Promise<T> {
    const r = await fetch(path);
    if (!r.ok) throw new Error(`${path}: ${r.status}`);
    return r.json();
  },
  wait: (ms: number) => new Promise((r) => setTimeout(r, ms)),
};

export const api = {
  status: async (): Promise<Snapshot> => {
    if (inTauri) return invoke<Snapshot>("status");
    if (browser.params().get("state") === "setup" || browser.params().get("state") === "off") {
      return { running: false, error: "makima is not running" };
    }
    try {
      return { running: true, status: await browser.get<Status>("/api/status") };
    } catch (e) {
      return { running: false, error: String(e) };
    }
  },
  environment: async (): Promise<Environment> => {
    if (inTauri) return invoke<Environment>("environment");
    const p = browser.params();
    return {
      cli: "/usr/local/bin/makima",
      member: p.get("state") !== "setup",
      holds_mesh: p.get("holds") !== "0",
      linked: p.get("linked") !== "0",
      platform: p.get("platform") ?? "macos",
      app_version: "dev",
    };
  },
  doctor: () => (inTauri ? invoke<{ checks: Check[] }>("doctor") : browser.get<{ checks: Check[] }>("/api/doctor")),
  ping: (peer: string) =>
    inTauri ? invoke<Ping>("ping", { peer }) : browser.get<Ping>(`/api/ping?peer=${encodeURIComponent(peer)}`),
  act: async (action: Action): Promise<Outcome> => {
    if (inTauri) return invoke<Outcome>("act", { action });
    await browser.wait(700);
    if (action.kind === "invite") {
      return {
        ok: true,
        output: JSON.stringify({
          words: "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve",
          invite: "mk1_eyJzIjoiaHR0cDovLzEwMC42NC4wLjE6ODA4MCIsImEiOiJta2F1dGgtZGV2LWV4YW1wbGUiLCJrIjoiZGV2In0",
        }),
      };
    }
    if (action.kind === "join" || action.kind === "up") {
      window.location.search = "?state=on";
    }
    if (action.kind === "down") window.location.search = "?state=off";
    return { ok: true, output: "" };
  },
  migrate: {
    detect: async (): Promise<Tailscale> => {
      if (inTauri) return invoke<Tailscale>("migrate_detect");
      const p = browser.params();
      if (p.get("tailscale") === "0") return { installed: false, running: false, peers: 0, online: 0 };
      return { installed: true, running: true, tailnet: "you.github", self: "macbook-air", peers: 4, online: 3 };
    },
    /// Listen to the migration's events. Returns the unsubscribe.
    listen: async (on: (e: MigrateEvent) => void): Promise<() => void> => {
      if (inTauri) {
        const { listen } = await import("@tauri-apps/api/event");
        return listen<MigrateEvent>("migrate", (e) => on(e.payload));
      }
      pretend.listeners.add(on);
      return () => pretend.listeners.delete(on);
    },
    scan: async (): Promise<void> => {
      if (inTauri) return invoke("migrate_scan");
      pretend.scan();
    },
    run: async (choice: Choice): Promise<void> => {
      if (inTauri) return invoke("migrate_run", { choice });
      pretend.run(choice);
    },
    stop: async (): Promise<void> => {
      if (inTauri) return invoke("migrate_stop");
    },
  },
  sendFile: async (peer: string, path: string): Promise<Outcome> => {
    if (inTauri) return invoke<Outcome>("send_file", { peer, path });
    await browser.wait(900);
    return { ok: true, output: "" };
  },
};

/// A pretend tailnet, for working on the migration screens in a browser.
/// Nothing here touches a machine; it only replays the events a real run
/// sends, with the timing roughly right.
const pretend = {
  listeners: new Set<(e: MigrateEvent) => void>(),
  send(e: MigrateEvent, after: number) {
    setTimeout(() => pretend.listeners.forEach((l) => l(e)), after);
  },
  machines(): Candidate[] {
    const f = (os: string, arch: string, user: string, sudo: Facts["sudo"], extra: Partial<Facts> = {}): Facts => ({ os, arch, user, sudo, ...extra });
    return [
      { id: "n1", name: "macbook-air", host: "MacBook Air", os: "macOS", ips: ["100.98.21.63"], online: true, local: true, facts: f("darwin", "arm64", "you", "password", { holds: true }), eligible: true, reach: "192.168.1.199", score: 0, pitch: "already holds a makima network" },
      { id: "n2", name: "tenet", host: "tenet", os: "linux", ips: ["100.102.72.87"], online: true, facts: f("linux", "amd64", "root", "root", { via: "tailscale" }), access: { user: "root" }, eligible: true, why: "reached through Tailscale SSH with no sshd behind it — makima's own SSH server takes over, with your keys", reach: "192.168.1.20", score: 10, pitch: "a server that stays on" },
      { id: "n3", name: "frieren", host: "frieren", os: "linux", ips: ["100.101.4.2"], online: true, facts: f("linux", "arm64", "pi", "password", { openssh: true }), access: { user: "" }, eligible: true, needs_password: true, reach: "192.168.1.31", score: 10, pitch: "a server that stays on" },
      { id: "n4", name: "vps", host: "vps", os: "linux", ips: ["100.90.8.8"], online: true, facts: f("linux", "amd64", "root", "root", { openssh: true }), access: { user: "root" }, eligible: true, public: "203.0.113.9", reach: "203.0.113.9", score: 70, pitch: "has a public address, so devices anywhere can reach it, and it can relay for them" },
      { id: "n5", name: "iphone", host: "iPhone", os: "iOS", ips: ["100.70.1.2"], online: true, eligible: false, why: "makima does not run on iPhone or iPad yet — it stays on Tailscale", score: 0 },
      { id: "n6", name: "old-desktop", host: "old-desktop", os: "linux", ips: ["100.85.1.1"], online: false, eligible: false, why: "offline — turn it on and scan again to bring it along", score: 0 },
    ];
  },
  scan() {
    const ms = pretend.machines();
    ms.forEach((m) => pretend.send({ type: "machine", machine: m.id, candidate: { ...m, eligible: false, why: undefined, facts: undefined, checking: true } }, 150));
    ms.forEach((m, i) => {
      if (m.id === "n2") {
        pretend.send({ type: "auth", machine: m.id, url: "https://login.tailscale.com/a/example" }, 500);
      }
      pretend.send({ type: "machine", machine: m.id, candidate: m }, m.id === "n2" ? 6000 : 500 + i * 400);
    });
    pretend.send({ type: "plan", plan: { tailnet: "you.github", machines: ms, controller: "n4", version: "dev" } }, 6200);
  },
  run(choice: Choice) {
    let t = 200;
    const step = (machine: string, s: string, state: "running" | "ok" | "failed", detail = "", gap = 700) => {
      pretend.send({ type: "step", machine, step: s, state, detail }, (t += gap));
    };
    const chosen = choice.plan.machines.filter((m) => choice.selected.includes(m.id) || m.id === choice.controller);
    const ctrl = chosen.find((m) => m.id === choice.controller)!;
    const others = chosen.filter((m) => m !== ctrl);
    for (const m of chosen.filter((m) => !m.local)) step(m.id, "install", "running", "putting makima on it", 250);
    for (const m of chosen.filter((m) => !m.local)) step(m.id, "install", "ok", "makima v0.3.0", 500);
    step(ctrl.id, "network", "running", `starting the network at ${choice.advertise || ctrl.reach}`);
    step(ctrl.id, "network", "ok", `holding the network at http://${choice.advertise || ctrl.reach}:8080`, 1200);
    for (const m of others) step(m.id, "reach", "running", `checking it can reach ${ctrl.name} without Tailscale`, 200);
    for (const m of others) step(m.id, "reach", "ok", "", 500);
    const local = chosen.find((m) => m.local);
    if (local && local !== ctrl) {
      pretend.send({ type: "prompt" }, (t += 300));
      step(local.id, "join", "running", "joining the network", 200);
      step(local.id, "join", "ok", "", 1400);
    }
    if (!ctrl.local) {
      step(ctrl.id, "switch", "running", "leaving Tailscale");
      step(ctrl.id, "switch", "running", "checking the tunnel", 1200);
      step(ctrl.id, "switch", "ok", "on makima, holding the network; Tailscale removed", 1500);
    }
    for (const m of others.filter((m) => !m.local)) step(m.id, "switch", "running", "leaving Tailscale", 200);
    for (const m of others.filter((m) => !m.local)) step(m.id, "switch", "ok", "on makima, direct; Tailscale removed", 1300);
    const self = ctrl.local ? ctrl : local;
    if (self) {
      pretend.send({ type: "prompt" }, (t += 300));
      step(self.id, "switch", "running", "leaving Tailscale", 200);
      step(self.id, "switch", "ok", "on makima, direct; Tailscale removed", 2000);
    }
    const result: MigrationResult = {
      ok: choice.plan.machines.every((m) => !m.eligible || chosen.includes(m)),
      server: `http://${choice.advertise || ctrl.reach}:8080`,
      controller: ctrl.id,
      machines: choice.plan.machines.map((m) =>
        chosen.includes(m)
          ? { id: m.id, name: m.name, outcome: "moved", detail: "on makima, direct; Tailscale removed" }
          : { id: m.id, name: m.name, outcome: "stayed", detail: m.why ?? "not chosen" },
      ),
    };
    pretend.send({ type: "result", result }, (t += 400));
    pretend.send({ type: "exit", code: 0 }, (t += 50));
  },
};

/// Open a URL in whatever handles it — a browser, or the terminal for ssh://.
export async function openExternal(url: string): Promise<void> {
  if (inTauri) {
    const { openUrl } = await import("@tauri-apps/plugin-opener");
    await openUrl(url);
  } else {
    window.open(url, "_blank");
  }
}

/// Reveal a folder in the file manager.
export async function openFolder(path: string): Promise<void> {
  if (!inTauri) return;
  const { openPath } = await import("@tauri-apps/plugin-opener");
  await openPath(path);
}

/// Put text on the clipboard.
export async function copyText(text: string): Promise<void> {
  if (inTauri) {
    const { writeText } = await import("@tauri-apps/plugin-clipboard-manager");
    await writeText(text);
  } else {
    await navigator.clipboard.writeText(text);
  }
}

/// Go durations arrive as nanoseconds. Rendered blank when unmeasured, because
/// "0 ms" reads as instantaneous, which is the opposite of the truth.
export function ms(ns: number): string {
  if (!ns) return "";
  const v = ns / 1e6;
  return v < 10 ? `${v.toFixed(1)} ms` : `${Math.round(v)} ms`;
}

/// A device's name with the mesh suffix, when names are on.
export function fqdn(name: string, status: Status): string | null {
  return status.dns_active && status.domain ? `${name}.${status.domain}` : null;
}

/// An invite as the CLI prints it with -json: the words to type, and the
/// string to paste. Older output — the bare string — is read too.
export type Invite = { words?: string; invite: string };

export function parseInvite(out: string): Invite | null {
  try {
    const j = JSON.parse(out.trim());
    if (j && typeof j.invite === "string") return { words: typeof j.words === "string" ? j.words : undefined, invite: j.invite };
  } catch {
    // Not JSON: fall through to the bare string.
  }
  const found = out.match(/mk[a-z0-9]*_[A-Za-z0-9_-]+/);
  return found ? { invite: found[0] } : null;
}

/// Whether text is something Join can take: the pasted string, or the words
/// — fifteen of them, or a typed server address followed by ten.
export function looksLikeInvite(text: string): boolean {
  const cleaned = text.trim().replace(/^makima\s+(join|up)\s+/i, "");
  if (/^mk1_[A-Za-z0-9_-]{16,}$/.test(cleaned)) return true;
  const words = cleaned.split(/\s+/).filter(Boolean);
  return words.length >= 11 && words.length <= 40 && words.every((w) => /^[A-Za-z0-9.:/\[\]-]+$/.test(w));
}

/// Whether a server URL points at a private address — a network that only
/// works from inside the building.
export function isPrivateServer(url: string | undefined): boolean {
  if (!url) return false;
  try {
    const host = new URL(url).hostname;
    return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(host) || host === "localhost";
  } catch {
    return false;
  }
}

/// One phrase for how a peer is being reached.
export function pathLabel(p: { direct: boolean; relay_url?: string; online: boolean }): string {
  if (!p.online) return "Offline";
  if (p.direct) return "Direct";
  if (p.relay_url) return "Via relay";
  return "No path";
}
