import { useEffect, useRef, useState } from "react";
import { isPrivateServer, parseInvite, type Environment, type Invite, type Status } from "./api";
import type { Act } from "./App";
import { Button, Code, Modal, Spinner, useCopied } from "./ui";
import { Icon } from "./icons";

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
  const [failed, setFailed] = useState(false);
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
      if (parsed) setInvite(parsed);
      else if (!serverless) setFailed(true);
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

  return (
    <Modal title="Add a device" onClose={onClose} width="max-w-[520px]">
      {!canMint ? (
        <div className="space-y-3 text-[13px] leading-relaxed text-dim">
          <p>
            Invites come from the device that started the network
            {status.server ? <> — <span className="font-mono text-ink">{hostOf(status.server)}</span></> : null}. Open makima there and
            choose Add device.
          </p>
        </div>
      ) : failed ? (
        <p className="text-[13px] leading-relaxed text-dim">
          No invite was made. The error is at the top of the window.
        </p>
      ) : !invite ? (
        <div className="flex items-center gap-2 py-6 text-[13px] text-dim">
          <Spinner /> {serverless ? "Publishing a pairing address…" : "Creating an invite…"}
        </div>
      ) : (
        <div className="space-y-4">
          <Step n={1}>
            Install makima on the other device and open it.
          </Step>
          <Step n={2}>
            {invite.words ? (
              <>
                Choose <b className="font-medium text-ink">Join a network</b> and type these words:
                <div className="selectable rounded-xl bg-card px-4 py-3 text-[15px] leading-relaxed text-ink">{invite.words}</div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-[12px] text-dimmer">Good for one device, for an hour. The first four letters of each word are enough.</span>
                  <Button
                    variant={copiedWords ? "default" : "primary"}
                    icon={copiedWords ? <Icon.Check /> : <Icon.Copy />}
                    onClick={() => copyWords(invite.words!)}
                  >
                    {copiedWords ? "Copied" : "Copy"}
                  </Button>
                </div>
              </>
            ) : (
              <>
                Choose <b className="font-medium text-ink">Join a network</b> and paste this:
                <Code>{invite.invite}</Code>
              </>
            )}
          </Step>
          <Step n={invite.words ? 3 : 3} muted>
            Or, if you can paste to it, this works there and in a terminal:
            <div className="flex items-center gap-2">
              <code className="selectable min-w-0 flex-1 truncate rounded-lg bg-card px-3 py-1.5 font-mono text-[11.5px] text-dim">{command}</code>
              <Button size="sm" icon={copiedCommand ? <Icon.Check /> : <Icon.Copy />} onClick={() => copyCommand(command)}>
                {copiedCommand ? "Copied" : "Copy"}
              </Button>
            </div>
            {!invite.words && (
              <span className="text-[12px] text-dimmer">
                {serverless
                  ? status.pairing
                    ? `Listening for one device until ${new Date(status.pairing.expires).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}.`
                    : "Listening for one device."
                  : "Good for one device, for an hour."}
              </span>
            )}
          </Step>
          {local && (
            <p className="rounded-lg bg-amber/10 px-3 py-2 text-[12.5px] leading-relaxed text-dim">
              This network is held at a private address, so the other device has to be on the same network as this one to
              join. From somewhere else, it cannot reach here.
            </p>
          )}
        </div>
      )}
      <div className="mt-5 flex justify-end">
        <Button onClick={onClose}>{invite || failed || !canMint ? "Done" : "Cancel"}</Button>
      </div>
    </Modal>
  );
}

function Step({ n, children, muted }: { n: number; children: React.ReactNode; muted?: boolean }) {
  return (
    <div className={`flex gap-3 ${muted ? "opacity-80" : ""}`}>
      <span className="mt-px flex size-5 shrink-0 items-center justify-center rounded-full bg-card-2 text-[11px] font-semibold text-dim">
        {n}
      </span>
      <div className="min-w-0 flex-1 space-y-2 text-[13px] leading-relaxed text-dim">{children}</div>
    </div>
  );
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
