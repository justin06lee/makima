import { useEffect, useRef, useState } from "react";
import { isPrivateServer, parseInvite, type Environment, type Invite, type Status } from "./api";
import type { Act } from "./App";
import { Button, Code, Modal, useCountdown } from "./ui";
import { Icon } from "./icons";
import { Iris } from "./Iris";
import { useCopy } from "./toast";
import { hostOf } from "./Device";

/// How long an invite is good for, from the moment it is made.
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
  const [showCommand, setShowCommand] = useState(false);
  const asked = useRef(false);
  const copy = useCopy();

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

  const expires = serverless ? (status.pairing ? new Date(status.pairing.expires).getTime() : null) : made ? made + INVITE_LIFE : null;
  const left = useCountdown(expires);
  const verb = serverless ? "pair" : "join";
  const command = invite ? `makima ${verb} ${invite.invite}` : "";
  const local = !serverless && isPrivateServer(status.server);
  const words = invite?.words?.split(/\s+/).filter(Boolean) ?? [];

  return (
    <Modal
      title="Add a device"
      subtitle={canMint ? "Three steps, on the other device." : undefined}
      onClose={onClose}
      width="max-w-[540px]"
      footer={
        <>
          {left && invite && (
            <span className="mr-auto flex items-center gap-1.5 text-[12px] text-dim">
              <Icon.Clock size={13} />
              Good for one device · <span className="tabular font-mono">{left}</span> left
            </span>
          )}
          <Button variant={invite ? "ink" : "default"} onClick={onClose}>
            {invite || failed || !canMint ? "Done" : "Cancel"}
          </Button>
        </>
      }
    >
      {!canMint ? (
        <div className="flex items-start gap-4 py-2">
          <Iris size={40} />
          <p className="text-[13px] leading-relaxed text-dim">
            Invites come from the device that holds the network
            {status.server ? (
              <>
                {" "}— <span className="font-mono text-ink">{hostOf(status.server)}</span>
              </>
            ) : null}
            . Open makima there and choose <b className="font-medium text-ink">Add device</b>.
          </p>
        </div>
      ) : failed ? (
        <p className="py-2 text-[13px] leading-relaxed text-dim">No invite was made. What went wrong is at the top of the window.</p>
      ) : !invite ? (
        <div className="flex flex-col items-center gap-3 py-10 text-[13px] text-dim">
          <Iris size={48} state="busy" />
          {serverless ? "Publishing a pairing address…" : "Making an invite…"}
        </div>
      ) : (
        <ol className="space-y-5">
          <Step n={1} title="Install makima on it and open it">
            The app, or the command line — either one can join.
          </Step>
          <Step n={2} title={words.length ? "Choose Join a network, and type these words" : "Choose Join a network, and paste this"}>
            {words.length ? (
              <div className="mt-2.5">
                <div className="selectable grid grid-cols-3 gap-1.5">
                  {words.map((w, i) => (
                    <div key={i} className="flex items-baseline gap-2 rounded-lg bg-raised px-2.5 py-1.5 shadow-[var(--shadow-sm)]">
                      <span className="tabular w-4 shrink-0 text-right font-mono text-[10px] text-dimmer">{i + 1}</span>
                      <span className="truncate font-mono text-[13px] font-medium text-ink">{w}</span>
                    </div>
                  ))}
                </div>
                <div className="mt-2.5 flex items-center justify-between gap-3">
                  <span className="text-[11.5px] text-dimmer">The first four letters of each word are enough.</span>
                  <Button size="sm" icon={<Icon.Copy size={13} />} onClick={() => copy(invite.words!, "the words")}>
                    Copy words
                  </Button>
                </div>
              </div>
            ) : (
              <div className="mt-2.5 space-y-2">
                <Code>{invite.invite}</Code>
                <Button size="sm" icon={<Icon.Copy size={13} />} onClick={() => copy(invite.invite, "the invite")}>
                  Copy invite
                </Button>
              </div>
            )}
          </Step>
          <Step n={3} title="That's it">
            It appears on your map within a few seconds, reachable by name.
            <button type="button" onClick={() => setShowCommand((v) => !v)} className="mt-2 flex items-center gap-1 text-[12px] font-medium text-dim transition hover:text-ink">
              <Icon.Chevron size={12} className={`transition ${showCommand ? "rotate-90" : ""}`} />
              Or from a terminal
            </button>
            {showCommand && (
              <div className="fade-in mt-2 flex items-center gap-2">
                <code className="selectable min-w-0 flex-1 truncate rounded-lg border border-line bg-sunken/60 px-3 py-1.5 font-mono text-[11px] text-dim">{command}</code>
                <Button size="sm" icon={<Icon.Copy size={13} />} onClick={() => copy(command, "the command")}>
                  Copy
                </Button>
              </div>
            )}
          </Step>
          {local && (
            <p className="flex gap-2 rounded-lg bg-amber/10 px-3 py-2.5 text-[12px] leading-relaxed text-dim">
              <Icon.Info size={14} className="mt-0.5 shrink-0 text-amber" />
              This network is held at a private address, so the other device has to be on the same network as this one
              to join.
            </p>
          )}
        </ol>
      )}
    </Modal>
  );
}

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <li className="flex gap-3.5">
      <span className="display flex size-6 shrink-0 items-center justify-center rounded-full bg-ink text-[12px] text-bg">{n}</span>
      <div className="min-w-0 flex-1 pt-0.5">
        <div className="text-[13.5px] font-semibold text-ink">{title}</div>
        <div className="mt-0.5 text-[12.5px] leading-relaxed text-dim">{children}</div>
      </div>
    </li>
  );
}
