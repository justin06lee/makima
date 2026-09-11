import { useEffect, useMemo, useRef, useState } from "react";
import { api, openExternal, type Candidate, type Choice, type MigrateEvent, type MigrationResult, type Plan } from "./api";
import { Button, Card, Input, Spinner, Toggle } from "./ui";
import { Icon } from "./icons";

/// Moving every device on a tailnet to makima, in one go.
///
/// Three screens. The first looks at every device, through Tailscale, and
/// changes nothing. The second is the one real decision — which device holds
/// the network, the Control Devil — plus what comes along. The third is the
/// move, device by device, controller first and this device last; anything
/// that does not come up on makima gets Tailscale back on its own.
type Phase = "scan" | "choose" | "run" | "done";

type Step = { step: string; state: "running" | "ok" | "failed"; detail?: string };

export function Migrate({ onClose, mac }: { onClose: () => void; mac: boolean }) {
  const [phase, setPhase] = useState<Phase>("scan");
  const [found, setFound] = useState<Record<string, Candidate>>({});
  const [auth, setAuth] = useState<Record<string, string>>({});
  const [plan, setPlan] = useState<Plan | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [controller, setController] = useState("");
  const [advertise, setAdvertise] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [passwords, setPasswords] = useState<Record<string, string>>({});
  const [remove, setRemove] = useState(true);

  const [steps, setSteps] = useState<Record<string, Step>>({});
  const [prompting, setPrompting] = useState(false);
  const [result, setResult] = useState<MigrationResult | null>(null);
  const phaseRef = useRef(phase);
  phaseRef.current = phase;

  // One listener for the whole sheet: scan and run speak the same stream.
  useEffect(() => {
    let off: (() => void) | undefined;
    let gone = false;
    api.migrate
      .listen((e: MigrateEvent) => {
        switch (e.type) {
          case "machine":
            setFound((f) => ({ ...f, [e.machine]: e.candidate }));
            setAuth((a) => {
              if (!a[e.machine] || e.candidate.access?.auth_url) return a;
              const { [e.machine]: _, ...rest } = a;
              return rest;
            });
            break;
          case "auth":
            setAuth((a) => ({ ...a, [e.machine]: e.url }));
            break;
          case "plan":
            setPlan(e.plan);
            setScanning(false);
            break;
          case "error":
            setError(e.detail);
            setScanning(false);
            break;
          case "prompt":
            setPrompting(true);
            break;
          case "step":
            setPrompting(false);
            setAuth((a) => {
              const { [e.machine]: _, ...rest } = a;
              return rest;
            });
            setSteps((s) => ({ ...s, [e.machine]: { step: e.step, state: e.state, detail: e.detail } }));
            break;
          case "result":
            setResult(e.result);
            phaseRef.current = "done";
            setPhase("done");
            break;
          case "exit":
            setScanning(false);
            setPrompting(false);
            if (phaseRef.current === "run") {
              setError(e.detail || "the move stopped without saying why");
              setPhase("done");
            }
            break;
        }
      })
      .then((un) => (gone ? un() : (off = un)));
    return () => {
      gone = true;
      off?.();
    };
  }, []);

  async function scan() {
    setFound({});
    setAuth({});
    setPlan(null);
    setError(null);
    setScanning(true);
    try {
      await api.migrate.scan();
    } catch (e) {
      setError(String(e));
      setScanning(false);
    }
  }

  // Start looking the moment the sheet opens.
  const started = useRef(false);
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void scan();
  }, []);

  // When the plan lands, preselect everything that can move and the
  // recommended controller.
  useEffect(() => {
    if (!plan) return;
    const movable = plan.machines.filter((m) => m.eligible);
    setSelected(new Set(movable.map((m) => m.id)));
    const rec = plan.controller ?? movable[0]?.id ?? "";
    setController(rec);
    setAdvertise(plan.machines.find((m) => m.id === rec)?.reach ?? "");
  }, [plan]);

  const machines = useMemo(() => orderMachines(plan, found), [plan, found]);
  const movable = machines.filter((m) => m.eligible);
  const staying = machines.filter((m) => !m.eligible);
  const ctrl = machines.find((m) => m.id === controller);
  const chosen = movable.filter((m) => selected.has(m.id) || m.id === controller);
  const missingPassword = chosen.filter((m) => m.needs_password && !passwords[m.id]);
  const left = [...staying, ...movable.filter((m) => !chosen.includes(m))];

  function pick(id: string) {
    setController(id);
    setAdvertise(machines.find((m) => m.id === id)?.reach ?? "");
    setSelected((s) => new Set(s).add(id));
  }

  async function move() {
    if (!plan || !ctrl) return;
    const choice: Choice = {
      plan,
      controller,
      advertise: advertise.trim() === ctrl.reach ? undefined : advertise.trim(),
      selected: chosen.map((m) => m.id),
      passwords: Object.fromEntries(chosen.filter((m) => m.needs_password).map((m) => [m.id, passwords[m.id] ?? ""])),
      remove_tailscale: remove,
    };
    setSteps({});
    setError(null);
    setPhase("run");
    try {
      await api.migrate.run(choice);
    } catch (e) {
      setError(String(e));
      setPhase("done");
    }
  }

  function close() {
    if (phase === "run") return;
    if (scanning) void api.migrate.stop();
    onClose();
  }

  const title = { scan: "Move from Tailscale", choose: "Choose the Control Devil", run: "Moving to makima", done: "Moved" }[phase];

  return (
    <div className="fade-in fixed inset-0 z-40 flex flex-col bg-bg">
      <header data-tauri-drag-region className={`flex h-[52px] shrink-0 items-center gap-3 border-b border-line pr-3 ${mac ? "pl-[84px]" : "pl-4"}`}>
        <div className="min-w-0 flex-1" data-tauri-drag-region>
          <div className="truncate text-[14px] font-semibold leading-tight" data-tauri-drag-region>
            {title}
          </div>
          <div className="truncate text-[12px] leading-tight text-dim" data-tauri-drag-region>
            {plan?.tailnet ? `Tailnet ${plan.tailnet}` : "Every device on your tailnet, onto makima"}
          </div>
        </div>
        <Stepper phase={phase} />
        <Button variant="ghost" onClick={close} disabled={phase === "run"} title={phase === "run" ? "Finishes on its own" : "Close"}>
          {phase === "done" ? "Done" : "Close"}
        </Button>
      </header>

      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[640px] space-y-5 px-6 pb-8 pt-5">
          {error && (
            <p className="selectable rounded-lg bg-red/8 px-3 py-2 text-[12.5px] leading-relaxed text-red">{error}</p>
          )}

          {phase === "scan" && <ScanList machines={machines} auth={auth} scanning={scanning} />}

          {phase === "choose" && (
            <>
              <section className="space-y-2">
                <p className="text-[13px] leading-relaxed text-dim">
                  One device holds the network together — the others join through it and find each other through it, the
                  way they used to through Tailscale's servers. Choose one that stays on, and that the others can reach.
                </p>
                <div className="space-y-2">
                  {[...movable].sort((a, b) => b.score - a.score).map((m) => (
                    <ControllerCard key={m.id} m={m} on={m.id === controller} recommended={m.id === plan?.controller} onPick={() => pick(m.id)}>
                      {m.id === controller && (
                        <div className="mt-3 space-y-1.5" onClick={(e) => e.stopPropagation()}>
                          <label className="text-[12px] text-dim">The other devices reach it at</label>
                          <Input value={advertise} onChange={setAdvertise} mono placeholder="an address, or https://a-name-you-own" />
                          <p className="text-[11.5px] leading-relaxed text-dimmer">
                            {m.public
                              ? "Its public address — reachable from anywhere. If it has a firewall, open TCP 8080 and 3478 and UDP 51820."
                              : "Its address on your home network. If a reverse proxy or a Cloudflare tunnel reaches this device from outside, put that name here instead."}
                          </p>
                        </div>
                      )}
                    </ControllerCard>
                  ))}
                </div>
                {plan?.advice && <p className="rounded-lg bg-amber/10 px-3 py-2 text-[12.5px] leading-relaxed text-dim">{plan.advice}</p>}
              </section>

              <section className="space-y-2">
                <h3 className="text-[15px] font-medium text-dim">Coming along</h3>
                <Card>
                  {movable.map((m) => (
                    <ComingRow
                      key={m.id}
                      m={m}
                      on={selected.has(m.id) || m.id === controller}
                      locked={m.id === controller}
                      onToggle={(on) =>
                        setSelected((s) => {
                          const n = new Set(s);
                          if (on) n.add(m.id);
                          else n.delete(m.id);
                          return n;
                        })
                      }
                      password={passwords[m.id] ?? ""}
                      setPassword={(v) => setPasswords((p) => ({ ...p, [m.id]: v }))}
                    />
                  ))}
                </Card>
              </section>

              {staying.length > 0 && (
                <section className="space-y-2">
                  <h3 className="text-[15px] font-medium text-dim">Staying on Tailscale</h3>
                  <Card>
                    {staying.map((m) => (
                      <MachineRow key={m.id} m={m} caption={m.why} dim />
                    ))}
                  </Card>
                </section>
              )}

              <section className="space-y-2">
                <Card>
                  <div className="flex items-center gap-3 px-4 py-3">
                    <div className="min-w-0 flex-1">
                      <div className="text-[14px] text-ink">Uninstall Tailscale from each device</div>
                      <div className="mt-0.5 text-[12px] leading-relaxed text-dim">
                        Only once that device is working on makima. One that does not come up on makima gets Tailscale back by itself.
                        {!remove && " Left off, Tailscale stays installed but switched off."}
                      </div>
                    </div>
                    <Toggle on={remove} onChange={setRemove} label="Uninstall Tailscale" />
                  </div>
                </Card>
                {remove && left.length > 0 && (
                  <p className="text-[12px] leading-relaxed text-dimmer">
                    Once this device is off Tailscale it can no longer reach {list(left.map((m) => m.name))}, which stay on it.
                  </p>
                )}
              </section>
            </>
          )}

          {(phase === "run" || phase === "done") && (
            <>
              {phase === "run" && prompting && (
                <p className="fade-in flex items-center gap-2 rounded-lg bg-accent/10 px-3 py-2 text-[12.5px] text-ink">
                  <Icon.Key className="text-accent" /> Your password is needed in the dialog to change this device.
                </p>
              )}
              {phase === "done" && result && <Summary result={result} removed={remove} />}
              <Card>
                {inOrder(chosen, controller).map((m) => (
                  <ProgressRow
                    key={m.id}
                    m={m}
                    step={steps[m.id]}
                    role={m.id === controller ? "Control Devil" : m.local ? "This device" : undefined}
                    auth={auth[m.id]}
                    outcome={result?.machines.find((o) => o.id === m.id)}
                    done={phase === "done"}
                  />
                ))}
              </Card>
              {phase === "run" && (
                <p className="text-[12px] leading-relaxed text-dimmer">
                  The device holding the network goes first and this one goes last. Each switches by itself once started, so
                  closing the window does not strand it halfway.
                </p>
              )}
            </>
          )}
        </div>
      </div>

      <footer className="flex h-[56px] shrink-0 items-center gap-3 border-t border-line px-4">
        {phase === "scan" && (
          <>
            <span className="flex-1 text-[12px] text-dim">
              {scanning ? (
                <span className="flex items-center gap-2">
                  <Spinner /> Looking at each device through Tailscale. Nothing changes yet.
                </span>
              ) : plan ? (
                `${plan.machines.filter((m) => m.eligible).length} of ${plan.machines.length} devices can move.`
              ) : (
                ""
              )}
            </span>
            {!scanning && (
              <Button onClick={scan} icon={<Icon.Pulse />}>
                Look again
              </Button>
            )}
            <Button variant="primary" disabled={!plan || movable.length === 0} onClick={() => setPhase("choose")}>
              Continue
            </Button>
          </>
        )}
        {phase === "choose" && (
          <>
            <Button variant="ghost" onClick={() => setPhase("scan")}>
              Back
            </Button>
            <span className="flex-1 text-right text-[12px] text-dim">
              {missingPassword.length > 0 ? `Enter the sudo password for ${list(missingPassword.map((m) => m.name))}.` : ctrl ? `${ctrl.name} will hold the network.` : ""}
            </span>
            <Button variant="primary" disabled={!ctrl || !advertise.trim() || missingPassword.length > 0} onClick={move}>
              Move {chosen.length} device{chosen.length === 1 ? "" : "s"}
            </Button>
          </>
        )}
        {phase === "run" && (
          <span className="flex flex-1 items-center gap-2 text-[12px] text-dim">
            <Spinner /> Moving. This takes a minute or two per device.
          </span>
        )}
        {phase === "done" && (
          <>
            <span className="flex-1 text-[12px] text-dim">{result?.server ? `The network is held at ${result.server}.` : ""}</span>
            <Button variant="primary" onClick={onClose}>
              Done
            </Button>
          </>
        )}
      </footer>
    </div>
  );
}

function Stepper({ phase }: { phase: Phase }) {
  const at = { scan: 0, choose: 1, run: 2, done: 2 }[phase];
  return (
    <ol className="hidden items-center gap-1.5 sm:flex" aria-label="Progress">
      {["Look", "Choose", "Move"].map((label, i) => (
        <li key={label} className="flex items-center gap-1.5">
          {i > 0 && <span className="h-px w-4 bg-line-2" />}
          <span className={`text-[12px] ${i === at ? "font-medium text-ink" : i < at ? "text-dim" : "text-dimmer"}`}>{label}</span>
        </li>
      ))}
    </ol>
  );
}

/// Scan results in the order the plan will show them, with machines still
/// being looked at in the order they arrived.
function orderMachines(plan: Plan | null, found: Record<string, Candidate>): Candidate[] {
  const all = plan ? plan.machines : Object.values(found);
  return [...all].sort((a, b) => {
    if (!!a.local !== !!b.local) return a.local ? -1 : 1;
    if (a.eligible !== b.eligible) return a.eligible ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
}

function osLabel(m: Candidate): string {
  const os = m.facts?.os === "darwin" || m.os === "macOS" ? "macOS" : m.os === "linux" ? "Linux" : m.os;
  return m.facts?.arch ? `${os} · ${m.facts.arch}` : os;
}

function ScanList({ machines, auth, scanning }: { machines: Candidate[]; auth: Record<string, string>; scanning: boolean }) {
  return (
    <section className="space-y-3">
      <p className="text-[13px] leading-relaxed text-dim">
        makima reaches each device the way you do today — over Tailscale, with SSH — to see whether it can move. Once
        every device is on makima, Tailscale can come off them.
      </p>
      <Card>
        {machines.length === 0 && (
          <div className="flex items-center gap-2 px-4 py-3 text-[13px] text-dim">{scanning ? <><Spinner /> Asking Tailscale for your devices…</> : "No devices."}</div>
        )}
        {machines.map((m) => (
          <MachineRow
            key={m.id}
            m={m}
            caption={m.checking ? (auth[m.id] ? undefined : "Looking…") : m.eligible ? readyCaption(m) : m.why}
            dim={!m.eligible && !m.checking}
            right={
              m.checking && !auth[m.id] ? (
                <Spinner className="text-dim" />
              ) : auth[m.id] ? (
                <Button size="sm" variant="primary" icon={<Icon.Open />} onClick={() => openExternal(auth[m.id])}>
                  Approve
                </Button>
              ) : m.eligible ? (
                <Icon.Check className="text-green" />
              ) : null
            }
            note={auth[m.id] ? "Tailscale SSH wants you to approve this login in your browser." : undefined}
          />
        ))}
      </Card>
    </section>
  );
}

function readyCaption(m: Candidate): string {
  const bits = [osLabel(m)];
  if (m.local) bits.push("this device");
  else if (m.facts?.user) bits.push(`as ${m.facts.user}`);
  if (m.needs_password) bits.push("needs its sudo password");
  if (m.facts?.makima) bits.push(`makima ${m.facts.makima} already there`);
  return bits.join(" · ");
}

function MachineRow({
  m,
  caption,
  right,
  dim,
  note,
}: {
  m: Candidate;
  caption?: string;
  right?: React.ReactNode;
  dim?: boolean;
  note?: string;
}) {
  return (
    <div className="flex items-center gap-3 border-b border-line px-4 py-2.5 last:border-0">
      <Icon.Devices className={dim ? "text-dimmer" : "text-dim"} />
      <div className="min-w-0 flex-1">
        <div className={`truncate text-[14px] ${dim ? "text-dim" : "text-ink"}`}>
          {m.name}
          {m.local && <span className="ml-2 text-[11px] font-medium text-dimmer">THIS DEVICE</span>}
        </div>
        {caption && <div className="mt-0.5 text-[12px] leading-snug text-dim">{caption}</div>}
        {note && <div className="mt-0.5 text-[12px] leading-snug text-amber">{note}</div>}
      </div>
      {right && <div className="flex shrink-0 items-center">{right}</div>}
    </div>
  );
}

function ControllerCard({
  m,
  on,
  recommended,
  onPick,
  children,
}: {
  m: Candidate;
  on: boolean;
  recommended: boolean;
  onPick: () => void;
  children?: React.ReactNode;
}) {
  return (
    <div
      role="radio"
      aria-checked={on}
      tabIndex={0}
      onClick={onPick}
      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onPick()}
      className={`cursor-pointer rounded-xl border px-4 py-3 transition ${on ? "border-accent bg-accent/5" : "border-line bg-card hover:border-line-2"}`}
    >
      <div className="flex items-center gap-3">
        <span className={`flex size-4 shrink-0 items-center justify-center rounded-full border ${on ? "border-accent" : "border-line-2"}`}>
          {on && <span className="size-2 rounded-full bg-accent" />}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-[14px] font-medium text-ink">{m.name}</span>
            {recommended && <span className="rounded-full bg-accent/12 px-2 py-px text-[11px] font-medium text-accent">Recommended</span>}
            {m.local && <span className="text-[11px] font-medium text-dimmer">THIS DEVICE</span>}
          </div>
          <div className="mt-0.5 text-[12px] leading-snug text-dim">
            {osLabel(m)}
            {m.pitch ? ` — ${m.pitch}` : ""}
          </div>
        </div>
      </div>
      {children}
    </div>
  );
}

function ComingRow({
  m,
  on,
  locked,
  onToggle,
  password,
  setPassword,
}: {
  m: Candidate;
  on: boolean;
  locked: boolean;
  onToggle: (on: boolean) => void;
  password: string;
  setPassword: (v: string) => void;
}) {
  return (
    <div className="border-b border-line px-4 py-2.5 last:border-0">
      <label className={`flex items-center gap-3 ${locked ? "" : "cursor-pointer"}`}>
        <input
          type="checkbox"
          checked={on}
          disabled={locked}
          onChange={(e) => onToggle(e.target.checked)}
          className="size-4 shrink-0 accent-[var(--accent)]"
        />
        <div className="min-w-0 flex-1">
          <div className="truncate text-[14px] text-ink">
            {m.name}
            {m.local && <span className="ml-2 text-[11px] font-medium text-dimmer">THIS DEVICE</span>}
          </div>
          <div className="mt-0.5 text-[12px] leading-snug text-dim">{locked ? "holds the network" : m.why ?? readyCaption(m)}</div>
        </div>
      </label>
      {on && m.needs_password && (
        <div className="ml-7 mt-2">
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={`sudo password for ${m.facts?.user ?? "its account"} on ${m.name}`}
            className="selectable h-8 w-full rounded-lg border border-line-2 bg-bg px-3 text-[13px] text-ink outline-none placeholder:text-dimmer focus:border-accent"
          />
        </div>
      )}
    </div>
  );
}

/// What a row says while a step runs with nothing more specific to say, and
/// once it has finished.
const stepLabel: Record<string, [string, string]> = {
  install: ["putting makima on it", "makima is on it — waiting its turn"],
  network: ["starting the network", "holding the network"],
  reach: ["checking it can reach the network", "can reach the network — waiting its turn"],
  join: ["joining the network", "joined — it leaves Tailscale last"],
  switch: ["leaving Tailscale", "on makima"],
};

function stepText(s: Step): string {
  const [running, ok] = stepLabel[s.step] ?? [s.step, s.step];
  if (s.state === "running") return s.detail || running;
  if (s.state === "ok") return s.step === "switch" || s.step === "network" ? s.detail || ok : ok;
  return s.detail || "failed";
}

function sentence(s: string): string {
  return s ? s[0].toUpperCase() + s.slice(1) : s;
}

/// The order things happen in: the controller, the rest, this device.
function inOrder(ms: Candidate[], controller: string): Candidate[] {
  const rank = (m: Candidate) => (m.id === controller ? 0 : m.local ? 2 : 1);
  return [...ms].sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));
}

function ProgressRow({
  m,
  step,
  role,
  auth,
  outcome,
  done,
}: {
  m: Candidate;
  step?: Step;
  role?: string;
  auth?: string;
  outcome?: { outcome: string; detail?: string; notes?: string[] };
  done: boolean;
}) {
  const failed = step?.state === "failed" || (outcome && outcome.outcome !== "moved" && outcome.outcome !== "moved?");
  const finished = outcome ? outcome.outcome === "moved" || outcome.outcome === "moved?" : step?.step === "switch" && step.state === "ok";
  const text = outcome?.detail ?? (step ? stepText(step) : "Waiting its turn");
  return (
    <div className="flex items-start gap-3 border-b border-line px-4 py-3 last:border-0">
      <span className="mt-0.5 flex size-4 shrink-0 items-center justify-center">
        {failed ? (
          <Icon.Close className="text-red" />
        ) : finished ? (
          <Icon.Check className="text-green" />
        ) : step && !done ? (
          <Spinner className="text-accent" />
        ) : (
          <span className="size-1.5 rounded-full bg-grey" />
        )}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-[14px] text-ink">{m.name}</span>
          {role && <span className="text-[11px] font-medium uppercase tracking-wide text-dimmer">{role}</span>}
        </div>
        <div className={`mt-0.5 text-[12px] leading-snug ${failed ? "text-red" : "text-dim"}`}>
          {sentence(text)}
        </div>
        {outcome?.notes?.map((n) => (
          <div key={n} className="mt-0.5 text-[11.5px] leading-snug text-dimmer">
            {n}
          </div>
        ))}
      </div>
      {auth && !done && (
        <Button size="sm" variant="primary" icon={<Icon.Open />} onClick={() => openExternal(auth)}>
          Approve
        </Button>
      )}
    </div>
  );
}

function Summary({ result, removed }: { result: MigrationResult; removed: boolean }) {
  const moved = result.machines.filter((m) => m.outcome === "moved" || m.outcome === "moved?").length;
  const tried = result.machines.filter((m) => m.outcome !== "stayed" || m.detail !== "not chosen").length;
  return (
    <div className="flex items-start gap-3 rounded-xl bg-card px-4 py-3">
      {result.ok ? <Icon.Check className="mt-0.5 text-green" /> : <Icon.Warn className="mt-0.5 text-amber" />}
      <div className="min-w-0 flex-1">
        <div className="text-[14px] font-medium text-ink">
          {result.ok ? `All ${moved} devices are on makima.` : `${moved} of ${tried} devices are on makima.`}
        </div>
        <div className="mt-0.5 text-[12.5px] leading-relaxed text-dim">
          {result.error
            ? result.error
            : result.ok
              ? `${removed ? "Tailscale is gone from each of them" : "Tailscale is switched off on each of them, still installed"}. Each device keeps the name it had on your tailnet, now under .makima, and ssh to it works as before.`
              : "The ones that did not move are exactly as they were, on Tailscale. Their reasons are below."}
        </div>
      </div>
    </div>
  );
}

function list(names: string[]): string {
  if (names.length <= 1) return names.join("");
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

/// The offer, where somebody who has Tailscale will see it: once on the first
/// screen, and as a strip over the device list until it is taken or dismissed.
export function TailscaleOffer({
  peers,
  onMove,
  onDismiss,
  compact,
}: {
  peers: number;
  onMove: () => void;
  onDismiss?: () => void;
  compact?: boolean;
}) {
  const others = peers === 1 ? "1 other device" : `${peers} other devices`;
  if (compact) {
    return (
      <div className="fade-in flex items-center gap-3 border-b border-line bg-accent/6 px-4 py-2.5">
        <Icon.Exit className="text-accent" />
        <p className="min-w-0 flex-1 text-[12.5px] leading-relaxed text-ink">
          Tailscale is running here, with {others}. Move them all to makima in one go.
        </p>
        <Button size="sm" variant="primary" onClick={onMove}>
          Move from Tailscale
        </Button>
        {onDismiss && (
          <button type="button" onClick={onDismiss} title="Not now" aria-label="Not now" className="text-dimmer hover:text-ink">
            <Icon.Close />
          </button>
        )}
      </div>
    );
  }
  return (
    <div className="flex w-full max-w-[640px] items-center gap-4 rounded-2xl border border-accent/30 bg-accent/6 p-5">
      <div className="min-w-0 flex-1">
        <h2 className="text-[16px] font-semibold">Coming from Tailscale?</h2>
        <p className="mt-1 text-[13px] leading-relaxed text-dim">
          It is running on this device, with {others}. makima can put itself on every one of them through Tailscale,
          connect them all, and take Tailscale off each once makima works there.
        </p>
      </div>
      <Button variant="primary" size="lg" onClick={onMove}>
        Move from Tailscale
      </Button>
    </div>
  );
}
