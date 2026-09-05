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
  /// How many connections could not reach the target. The number worth
  /// looking at: a published port with nothing behind it refuses every
  /// attempt, and that is the usual misconfiguration.
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
  | { kind: "down" }
  | { kind: "allow"; port: number }
  | { kind: "deny"; port: number }
  | { kind: "exit-node"; name: string }
  | { kind: "invite" }
  | { kind: "pair" };

export const api = {
  status: () => invoke<Snapshot>("status"),
  doctor: () => invoke<{ checks: Check[] }>("doctor"),
  ping: (peer: string) => invoke<Ping>("ping", { peer }),
  act: (action: Action) => invoke<Outcome>("act", { action }),
};

/// Go durations arrive as nanoseconds. Rendered blank when unmeasured, because
/// "0ms" reads as instantaneous, which is the opposite of the truth.
export function ms(ns: number): string {
  if (!ns) return "";
  const v = ns / 1e6;
  return v < 10 ? `${v.toFixed(1)}ms` : `${Math.round(v)}ms`;
}
