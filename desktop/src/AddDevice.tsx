import { useEffect, useRef, useState } from "react";
import { isPrivateServer, parseInvite, type Environment, type Invite, type Status } from "./api";
import type { Act } from "./App";
import { Button, Code, Modal, Spinner, useCopied } from "./ui";
import { Icon } from "./icons";

/// How long an invite is good for, as the CLI makes them.
const INVITE_LIFE = 60 * 60 * 1000;

/// Adding a device: an invite for a network with a server, a pairing address
/// for one without. The window never has to explain which; it asks the daemon
/// what kind of network this is and offers the right one.
///
/// An invite comes in two shapes. Fifteen words are what a person types into
/// the other machine's app — that machine is not on the network yet, so
/// nothing can be pasted to it. The mk1_ string is for when something can.
export function AddDevice({
  status,
  env,
  act,
  onClose,
}: {
  status: Status;
  env: Environment;
  act: Act;
  onClose: () => void;
}) {
  const serverless = status.serverless;
  const canMint = env.holds_mesh || serverless;
  const [invite, setInvite] = useState<Invite | null>(serverless && status.pairing?.address ? { invite: status.pairing.address } : null);
  const [made, setMade] = useState<number | null>(null);
  const [failed, setFailed] = useState(false);
  const [terminal, setTerminal] = useState(false);
  const asked = useRef(false);

  // Ask the moment the sheet opens, once. The prompt for root is the first
  // thing the person sees, and it says what it is for.
  useEffect(() => {
    if (asked.current || invite || !canMint) return;
    asked.current = true;
    (async () => {
      const out = await act({ kind: serverless ? "pair" : "invite" });
      if (out === null) {
        setFailed(true);
        return;
      }
      const parsed = parseInvite(out);
      if (parsed) {
        setInvite(parsed);
        setMade(Date.now());
      } else if (!serverless) setFailed(true);
    })();
  }, [act, canMint, serverless, invite]);

  // A pairing address is published by the daemon, and arrives with the next
  // status rather than from the command's output.
  useEffect(() => {
    if (serverless && status.pairing?.address) setInvite({ invite: status.pairing.address });
  }, [serverless, status.pairing]);

  const verb = serverless ? "pair" : "join";
  const command = invite ? `makima ${verb} ${invite.invite}` : "";
  const [copiedWords, copyWords] = useCopied();
  const [copiedCommand, copyCommand] = useCopied();
  const local = !serverless && isPrivateServer(status.server);
  const expires = serverless && status.pairing ? new Date(status.pairing.expires).getTime() : made ? made + INVITE_LIFE : null;
  const left = useCountdown(expires);
  const words = invite?.words?.split(/\s+/).filter(Boolean) ?? [];

  return (
    <Modal
      title="Add a device"
      sub={canMint && invite ? (words.length ? "Install makima on the other device, choose Join a network, and type these words." : "Install makima on the other device, choose Join a network, and paste this.") : undefined}
      onClose={onClose}
      width="max-w-[500px]"
      footer={
        <>
          {left && <span className="tabular mr-auto text-[12px] text-dim">{left === "expired" ? "This invite has expired" : `Good for one device · expires in ${left}`}</span>}
          <Button onClick={onClose}>{invite || failed || !canMint ? "Done" : "Cancel"}</Button>
        </>
      }
    >
      {!canMint ? (
        <p className="text-[13px] leading-relaxed text-dim">
          Invites come from the device that holds the network
          {status.server ? (
            <>
              {" "}— <span className="font-mono text-ink">{hostOf(status.server)}</span>
            </>
          ) : null}
          . Open makima there and choose Add device.
        </p>
      ) : failed ? (
        <p className="text-[13px] leading-relaxed text-dim">No invite was made. The error is at the top of the window.</p>
      ) : !invite ? (
        <div className="flex flex-col items-center gap-3 py-10 text-[13px] text-dim">
          <Spinner className="size-5" />
          {serverless ? "Publishing a pairing address…" : "Making an invite…"}
        </div>
      ) : (
        <div className="space-y-4">
          {words.length > 0 ? (
            <div>
              <ol className="selectable grid grid-cols-3 gap-x-2 gap-y-1.5 rounded-xl border border-line bg-sunken/60 p-3">
                {words.map((w, i) => (
                  <li key={i} className="flex h-8 items-center gap-2 rounded-lg bg-panel px-2.5 shadow-[0_0_0_1px_var(--line)]">
                    <span className="tabular w-4 shrink-0 text-right text-[10.5px] text-dimmer">{i + 1}</span>
                    <span className="truncate font-mono text-[13px] font-medium text-ink">{w}</span>
                  </li>
                ))}
              </ol>
              <div className="mt-3 flex items-center justify-between gap-3">
                <span className="text-[12px] text-dimmer">The first four letters of each word are enough.</span>
                <Button variant={copiedWords ? "default" : "primary"} size="sm" icon={copiedWords ? <Icon.Check size={14} /> : <Icon.Copy size={14} />} onClick={() => copyWords(invite.words!, "the words")}>
                  {copiedWords ? "Copied" : "Copy words"}
                </Button>
              </div>
            </div>
          ) : (
            <Code>{invite.invite}</Code>
          )}

          <div className="rounded-xl border border-line">
            <button type="button" onClick={() => setTerminal((t) => !t)} className="flex w-full items-center gap-2 px-3.5 py-2.5 text-left text-[12.5px] text-dim hover:text-ink">
              <Icon.Terminal size={14} />
              <span className="flex-1">{words.length ? "Or paste a command instead" : "The same, as a command"}</span>
              <Icon.ChevronDown size={14} className={`transition-transform ${terminal ? "rotate-180" : ""}`} />
            </button>
            {terminal && (
              <div className="fade-in flex items-center gap-2 border-t border-line px-3.5 py-2.5">
                <code className="selectable min-w-0 flex-1 truncate font-mono text-[11.5px] text-dim">{command}</code>
                <Button size="sm" icon={copiedCommand ? <Icon.Check size={14} /> : <Icon.Copy size={14} />} onClick={() => copyCommand(command, "the command")}>
                  {copiedCommand ? "Copied" : "Copy"}
                </Button>
              </div>
            )}
          </div>

          {local && (
            <p className="flex gap-2.5 rounded-xl border border-amber/25 bg-amber/[0.07] px-3.5 py-2.5 text-[12px] leading-relaxed text-ink-2">
              <Icon.Warn size={14} className="mt-0.5 shrink-0 text-amber" />
              This network is held at a private address, so the other device has to be on the same local network to join.
            </p>
          )}
        </div>
      )}
    </Modal>
  );
}

/// "54 min", counting down once a second while the sheet is open.
function useCountdown(until: number | null): string | null {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!until) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [until]);
  if (!until) return null;
  const s = Math.floor((until - now) / 1000);
  if (s <= 0) return "expired";
  if (s < 60) return `${s}s`;
  return `${Math.ceil(s / 60)} min`;
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
