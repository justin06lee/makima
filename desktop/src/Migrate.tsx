import { useEffect, useMemo, useRef, useState } from "react";
import { api, openExternal, type Candidate, type Choice, type MigrateEvent, type MigrationResult, type Plan } from "./api";
import { Button, Card, IconButton, Input, Spinner, Tag, Toggle } from "./ui";
import { Iris } from "./Iris";
import { Icon } from "./icons";

/// Moving every device on a tailnet to makima, in one go.
///
/// Three screens. The first looks at every device, through Tailscale, and
/// changes nothing. The second is the one real decision — which device holds
/// the network, the Control Devil — plus what comes along. The third is the
/// move: makima goes on beside Tailscale everywhere, and Tailscale comes off a
/// device only once this one has reached it over makima.
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
  const chosen = movable.filter((m) => selected.has(m.id) || m.id === controller || m.local);
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
      <header data-tauri-drag-region className={`flex h-[52px] shrink-0 items-center gap-3 border-b border-line bg-panel/70 pr-3 ${mac ? "pl-[84px]" : "pl-4"}`}>
        <Iris size={22} state={phase === "run" || scanning ? "busy" : "on"} />
        <div className="min-w-0 flex-1" data-tauri-drag-region>
          <div className="display truncate text-[14px] leading-tight" data-tauri-drag-region>
            {title}
          </div>
          <div className="truncate text-[11.5px] leading-tight text-dim" data-tauri-drag-region>
            {plan?.tailnet ? `Tailnet ${plan.tailnet}` : "Every device on your tailnet, onto makima"}
          </div>
        </div>
        <Stepper phase={phase} />
        <Button variant="ghost" onClick={close} disabled={phase === "run"} title={phase === "run" ? "Finishes on its own" : "Close"}>
          {phase === "done" ? "Done" : "Close"}
        </Button>
      </header>

      <div className="grain min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[660px] space-y-7 px-7 pb-10 pt-7">
          {error && (
            <p className="selectable flex gap-2 rounded-xl bg-red/8 px-3.5 py-2.5 text-[12.5px] leading-relaxed text-red">
              <Icon.Warn size={14} className="mt-0.5 shrink-0" />
              {error}
            </p>
          )}

          {phase === "scan" && <ScanList machines={machines} auth={auth} scanning={scanning} />}

          {phase === "choose" && (
            <>
              <section className="space-y-3">
                <Lead title="Which device holds the network?">
                  The others join through it and find each other through it, the way they used to through Tailscale's
                  servers. Choose one that stays on, and that the others can reach.
                </Lead>
                <div className="space-y-2">
                  {[...movable].sort((a, b) => b.score - a.score).map((m) => (
                    <ControllerCard key={m.id} m={m} on={m.id === controller} recommended={m.id === plan?.controller} onPick={() => pick(m.id)}>
                      {m.id === controller && (
                        <div className="mt-3.5 space-y-1.5 border-t border-line pt-3" onClick={(e) => e.stopPropagation()}>
                          <label className="caps text-dimmer">The others reach it at</label>
                          <Input value={advertise} onChange={setAdvertise} mono placeholder="an address, or https://a-name-you-own" />
                          <p className="text-[11.5px] leading-relaxed text-dimmer">
                            {m.public
                              ? "Its public address — reachable from anywhere. makima opens its own ports in the device's firewall; a cloud provider's firewall still needs TCP 8080 and UDP 51820 open."
                              : "Its address on your home network. If a reverse proxy or a Cloudflare tunnel reaches this device from outside, put that name here instead."}
                          </p>
                        </div>
                      )}
                    </ControllerCard>
                  ))}
                </div>
                {plan?.advice && (
                  <p className="flex gap-2 rounded-xl bg-amber/10 px-3.5 py-2.5 text-[12.5px] leading-relaxed text-dim">
                    <Icon.Info size={14} className="mt-0.5 shrink-0 text-amber" />
                    {plan.advice}
                  </p>
                )}
              </section>

              <section className="space-y-2.5">
                <h3 className="caps text-dimmer">Coming along</h3>
                <Card>
                  {movable.map((m) => (
                    <ComingRow
                      key={m.id}
                      m={m}
                      on={selected.has(m.id) || m.id === controller || !!m.local}
                      locked={m.id === controller || !!m.local}
                      role={
                        m.id === controller
                          ? m.local
                            ? "holds the network, and reaches each of the others over makima"
                            : "holds the network"
                          : m.local
                            ? "always comes along — it reaches each of the others over makima"
                            : undefined
                      }
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
                <section className="space-y-2.5">
                  <h3 className="caps text-dimmer">Staying on Tailscale</h3>
                  <Card>
                    {staying.map((m) => (
                      <MachineRow key={m.id} m={m} caption={m.why} dim />
                    ))}
                  </Card>
                </section>
              )}

              <section className="space-y-2">
                <Card>
                  <div className="flex items-center gap-3 px-4 py-3.5">
                    <div className="min-w-0 flex-1">
                      <div className="text-[13.5px] font-medium text-ink">Uninstall Tailscale from each device</div>
                      <div className="mt-0.5 text-[12px] leading-relaxed text-dim">
                        Only once this device has logged in to it over makima. Until then Tailscale keeps running beside
                        makima, so a device that does not come up is exactly as reachable as before.
                        {!remove && " Left off, Tailscale keeps running beside makima everywhere."}
                      </div>
                    </div>
                    <Toggle on={remove} onChange={setRemove} label="Uninstall Tailscale" />
                  </div>
                </Card>
                {remove && left.length > 0 && (
                  <p className="px-1 text-[12px] leading-relaxed text-dimmer">
                    Once this device is off Tailscale it can no longer reach {list(left.map((m) => m.name))}, which stay on it.
                  </p>
                )}
              </section>
            </>
          )}

          {(phase === "run" || phase === "done") && (
            <>
              {phase === "run" && prompting && (
                <p className="fade-in flex items-center gap-2 rounded-xl bg-accent/10 px-3.5 py-2.5 text-[12.5px] text-ink">
                  <Icon.Key size={14} className="text-accent" /> Your password is needed in the dialog to change this device.
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
                <p className="px-1 text-[12px] leading-relaxed text-dimmer">
                  Tailscale keeps running on every device until this one has logged in to it over makima. A device that
                  cannot be reached that way keeps Tailscale, and is exactly as reachable as it was.
                </p>
              )}
            </>
          )}
        </div>
      </div>

      <footer className="flex h-[58px] shrink-0 items-center gap-3 border-t border-line bg-panel/70 px-4">
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
              <Button onClick={scan} icon={<Icon.Pulse size={14} />}>
                Look again
              </Button>
            )}
            <Button variant="primary" disabled={!plan || movable.length === 0} onClick={() => setPhase("choose")} icon={<Icon.ArrowRight size={14} />}>
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
            <span className="flex-1 truncate text-[12px] text-dim">{result?.server ? `The network is held at ${result.server}.` : ""}</span>
            <Button variant="primary" onClick={onClose}>
              Done
            </Button>
          </>
        )}
      </footer>
    </div>
  );
}

function Lead({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h2 className="display text-[20px] leading-tight">{title}</h2>
      <p className="mt-1.5 text-[13px] leading-relaxed text-dim">{children}</p>
    </div>
  );
}

function Stepper({ phase }: { phase: Phase }) {
  const at = { scan: 0, choose: 1, run: 2, done: 3 }[phase];
  return (
    <ol className="mr-2 hidden items-center gap-2 sm:flex" aria-label="Progress">
      {["Look", "Choose", "Move"].map((label, i) => (
        <li key={label} className="flex items-center gap-2">
          {i > 0 && <span className={`h-px w-5 ${i <= at ? "bg-ink/40" : "bg-line-2"}`} />}
          <span
            className={`flex size-[18px] items-center justify-center rounded-full text-[10px] font-semibold transition
              ${i < at ? "bg-ink text-bg" : i === at ? "bg-accent text-accent-ink" : "border border-line-2 text-dimmer"}`}
          >
            {i < at ? <Icon.Check size={11} /> : i + 1}
          </span>
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

function OsIcon({ m, className = "" }: { m: Candidate; className?: string }) {
  const os = (m.facts?.os ?? m.os).toLowerCase();
  if (os === "darwin" || os === "macos") return <Icon.Laptop className={className} />;
  if (os === "linux") return <Icon.Server className={className} />;
  return <Icon.Devices className={className} />;
}

function ScanList({ machines, auth, scanning }: { machines: Candidate[]; auth: Record<string, string>; scanning: boolean }) {
  const ready = machines.filter((m) => m.eligible).length;
  return (
    <section className="space-y-4">
      <Lead title={scanning ? "Looking at your devices" : `${ready} of ${machines.length} can move`}>
        makima reaches each device the way you do today — over Tailscale, with SSH — to see whether it can move. Nothing
        changes yet. Once every device is on makima, Tailscale can come off them.
      </Lead>
      <Card>
        {machines.length === 0 && (
          <div className="flex items-center gap-2 px-4 py-3.5 text-[13px] text-dim">{scanning ? <><Spinner /> Asking Tailscale for your devices…</> : "No devices."}</div>
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
                <Button size="sm" variant="primary" icon={<Icon.Open size={13} />} onClick={() => openExternal(auth[m.id])}>
                  Approve
                </Button>
              ) : m.eligible ? (
                <span className="flex items-center gap-1 text-[12px] text-green">
                  <Icon.Check size={14} /> Ready
                </span>
              ) : (
                <span className="text-[12px] text-dimmer">Stays</span>
              )
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
    <div className="flex items-center gap-3 border-b border-line px-4 py-3 last:border-0">
      <span className={`flex size-8 shrink-0 items-center justify-center rounded-lg bg-raised-2 ${dim ? "text-dimmer" : "text-dim"}`}>
        <OsIcon m={m} />
      </span>
      <div className="min-w-0 flex-1">
        <div className={`flex items-center gap-2 truncate text-[13.5px] font-medium ${dim ? "text-dim" : "text-ink"}`}>
          {m.name}
          {m.local && <Tag>this device</Tag>}
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
      className={`cursor-pointer rounded-xl bg-raised px-4 py-3.5 transition
        ${on ? "shadow-[0_0_0_1.5px_var(--accent),0_0_0_6px_var(--focus)]" : "shadow-[var(--shadow-sm)] hover:bg-raised-2"}`}
    >
      <div className="flex items-center gap-3">
        <span className={`flex size-9 shrink-0 items-center justify-center rounded-lg ${on ? "bg-accent text-accent-ink" : "bg-raised-2 text-dim"}`}>
          <OsIcon m={m} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-[14px] font-semibold text-ink">{m.name}</span>
            {recommended && <Tag tone="accent">Recommended</Tag>}
            {m.local && <Tag>this device</Tag>}
          </div>
          <div className="mt-0.5 text-[12px] leading-snug text-dim">
            {osLabel(m)}
            {m.pitch ? ` — ${m.pitch}` : ""}
          </div>
        </div>
        <span className={`flex size-[18px] shrink-0 items-center justify-center rounded-full border-[1.5px] ${on ? "border-accent bg-accent" : "border-line-2"}`}>
          {on && <span className="size-1.5 rounded-full bg-white" />}
        </span>
      </div>
      {children}
    </div>
  );
}

function ComingRow({
  m,
  on,
  locked,
  role,
  onToggle,
  password,
  setPassword,
}: {
  m: Candidate;
  on: boolean;
  locked: boolean;
  role?: string;
  onToggle: (on: boolean) => void;
  password: string;
  setPassword: (v: string) => void;
}) {
  return (
    <div className="border-b border-line px-4 py-3 last:border-0">
      <label className={`flex items-center gap-3 ${locked ? "" : "cursor-pointer"}`}>
        <input type="checkbox" checked={on} disabled={locked} onChange={(e) => onToggle(e.target.checked)} className="peer sr-only" />
        <span
          className={`flex size-[18px] shrink-0 items-center justify-center rounded-[5px] border-[1.5px] transition peer-focus-visible:shadow-[0_0_0_3px_var(--focus)]
            ${on ? (locked ? "border-dimmer bg-dimmer text-bg" : "border-ink bg-ink text-bg") : "border-line-2"}`}
        >
          {on && <Icon.Check size={12} />}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 truncate text-[13.5px] font-medium text-ink">
            {m.name}
            {m.local && <Tag>this device</Tag>}
          </div>
          <div className="mt-0.5 text-[12px] leading-snug text-dim">{role ?? m.why ?? readyCaption(m)}</div>
        </div>
      </label>
      {on && m.needs_password && (
        <div className="ml-[30px] mt-2.5">
          <Input type="password" value={password} onChange={setPassword} placeholder={`sudo password for ${m.facts?.user ?? "its account"} on ${m.name}`} />
        </div>
      )}
    </div>
  );
}

/// What a row says while a step runs with nothing more specific to say, and
/// once it has finished.
const stepLabel: Record<string, [string, string]> = {
  install: ["putting makima on it", "makima is on it — waiting its turn"],
  keys: ["adding your SSH keys", "your SSH keys are there"],
  network: ["starting the network", "holding the network"],
  join: ["joining the network", "on the network, beside Tailscale"],
  verify: ["reaching it over makima", "reached over makima"],
  remove: ["removing Tailscale", "Tailscale removed"],
};

function stepText(s: Step): string {
  const [running, ok] = stepLabel[s.step] ?? [s.step, s.step];
  if (s.state === "running") return s.detail || running;
  if (s.state === "ok") return s.detail || ok;
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
  // Red is for a device something went wrong on. One the run stopped short
  // of was never touched, and says so in grey. Amber is on makima with
  // Tailscale still beside it.
  const on = outcome?.outcome === "moved" || outcome?.outcome === "both";
  const failed = !on && step?.state === "failed";
  const finished = outcome ? on : step?.step === "remove" && step.state === "ok";
  const text = outcome?.detail ?? (step ? stepText(step) : "Waiting its turn");
  return (
    <div className="flex items-start gap-3 border-b border-line px-4 py-3 last:border-0">
      <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center">
        {failed ? (
          <span className="flex size-5 items-center justify-center rounded-full bg-red/12 text-red">
            <Icon.Close size={12} />
          </span>
        ) : finished ? (
          <span className={`flex size-5 items-center justify-center rounded-full ${outcome?.outcome === "both" ? "bg-amber/15 text-amber" : "bg-green/15 text-green"}`}>
            <Icon.Check size={12} />
          </span>
        ) : step && !done ? (
          <Spinner className="text-accent" />
        ) : (
          <span className="size-1.5 rounded-full bg-grey" />
        )}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-[13.5px] font-medium text-ink">{m.name}</span>
          {role && <Tag tone={role === "Control Devil" ? "accent" : "plain"}>{role}</Tag>}
        </div>
        <div className={`mt-0.5 text-[12px] leading-snug ${failed ? "text-red" : "text-dim"}`}>{sentence(text)}</div>
        {outcome?.notes?.map((n) => (
          <div key={n} className="mt-0.5 text-[11.5px] leading-snug text-dimmer">
            {n}
          </div>
        ))}
      </div>
      {auth && !done && (
        <Button size="sm" variant="primary" icon={<Icon.Open size={13} />} onClick={() => openExternal(auth)}>
          Approve
        </Button>
      )}
    </div>
  );
}

function Summary({ result, removed }: { result: MigrationResult; removed: boolean }) {
  const on = result.machines.filter((m) => m.outcome === "moved" || m.outcome === "both").length;
  const tried = result.machines.filter((m) => m.outcome !== "stayed" || m.detail !== "not chosen").length;
  return (
    <div className="rise flex items-start gap-4 rounded-2xl bg-raised px-5 py-4 shadow-[var(--shadow-sm)]">
      <Iris size={44} state={result.ok ? "on" : "off"} />
      <div className="min-w-0 flex-1">
        <div className="display text-[18px] leading-tight">{result.ok ? `All ${on} devices are on makima.` : `${on} of ${tried} devices are on makima.`}</div>
        <div className="mt-1 text-[12.5px] leading-relaxed text-dim">
          {result.error
            ? result.error
            : result.ok
              ? `${removed ? "Tailscale is gone from each of them" : "Tailscale is still running beside makima on each of them"}. Each device keeps the name it had on your tailnet, now under .makima, and ssh to it works as before.`
              : "Tailscale was never stopped on the rest, so they are exactly as reachable as they were. Their reasons are below."}
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
      <div className="fade-in flex items-center gap-3 border-b border-line bg-raised px-4 py-2">
        <Icon.Exit size={14} className="text-accent" />
        <p className="min-w-0 flex-1 truncate text-[12.5px] text-ink">
          Tailscale is running here with {others}. <span className="text-dim">Move them all to makima in one go.</span>
        </p>
        <Button size="sm" onClick={onMove} icon={<Icon.ArrowRight size={13} />}>
          Move from Tailscale
        </Button>
        {onDismiss && (
          <IconButton onClick={onDismiss} title="Not now" size="sm">
            <Icon.Close size={14} />
          </IconButton>
        )}
      </div>
    );
  }
  return (
    <button
      type="button"
      onClick={onMove}
      className="group flex w-full items-center gap-3 rounded-xl border border-line-2 px-3.5 py-2.5 text-left transition hover:border-dimmer hover:bg-raised"
    >
      <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-accent/10 text-accent">
        <Icon.Exit size={15} />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-[13px] font-semibold">Coming from Tailscale?</span>
        <span className="block truncate text-[12px] text-dim">Move this device and its {others} over in one go.</span>
      </span>
      <Icon.ArrowRight size={15} className="text-dim transition group-hover:translate-x-0.5 group-hover:text-ink" />
    </button>
  );
}
