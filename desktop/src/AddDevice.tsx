import { useEffect, useRef, useState } from "react";
import type { Environment, Status } from "./api";
import type { Act } from "./App";
import { Button, Code, Modal, Spinner, useCopied } from "./ui";
import { Icon } from "./icons";

/// Adding a device: an invite for a network with a server, a pairing address
/// for one without. The window never has to explain which; it asks the daemon
/// what kind of network this is and offers the right one.
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
  const [token, setToken] = useState<string | null>(serverless ? status.pairing?.address ?? null : null);
  const [failed, setFailed] = useState(false);
  const asked = useRef(false);

  // Ask the moment the sheet opens, once. The prompt for root is the first
  // thing the person sees, and it says what it is for.
  useEffect(() => {
    if (asked.current || token || !canMint) return;
    asked.current = true;
    (async () => {
      const out = await act({ kind: serverless ? "pair" : "invite" });
      if (out === null) {
        setFailed(true);
        return;
      }
      const found = out.match(/mk[a-z0-9]*_[A-Za-z0-9_-]+/);
      if (found) setToken(found[0]);
      else if (!serverless) setFailed(true);
    })();
  }, [act, canMint, serverless, token]);

  // A pairing address is published by the daemon, and arrives with the next
  // status rather than from the command's output.
  useEffect(() => {
    if (serverless && status.pairing?.address) setToken(status.pairing.address);
  }, [serverless, status.pairing]);

  const verb = serverless ? "pair" : "join";
  const command = token ? `makima ${verb} ${token}` : "";
  const [copied, copy] = useCopied();

  return (
    <Modal title="Add a device" onClose={onClose}>
      {!canMint ? (
        <div className="space-y-3 text-[13px] leading-relaxed text-dim">
          <p>
            Invites come from the device holding the network
            {status.server ? <> — <span className="font-mono text-ink">{hostOf(status.server)}</span></> : null}. Open makima there and
            choose Add device, or run:
          </p>
          <Code>makima invite</Code>
        </div>
      ) : failed ? (
        <p className="text-[13px] leading-relaxed text-dim">
          No invite was made. The error is at the top of the window.
        </p>
      ) : !token ? (
        <div className="flex items-center gap-2 py-6 text-[13px] text-dim">
          <Spinner /> {serverless ? "Publishing a pairing address…" : "Creating an invite…"}
        </div>
      ) : (
        <div className="space-y-4">
          <Step n={1}>
            Install makima on the other device — the app, or in a terminal:
            <Code>curl -fsSL https://raw.githubusercontent.com/justin06lee/makima/master/dist/install.sh | sh</Code>
          </Step>
          <Step n={2}>
            {serverless ? (
              <>Paste this there, in the app under <b className="font-medium text-ink">Join a network</b>, or in a terminal:</>
            ) : (
              <>Paste this invite there, in the app under <b className="font-medium text-ink">Join a network</b>, or in a terminal:</>
            )}
            <Code>{command}</Code>
            <div className="flex items-center justify-between gap-3">
              <span className="text-[12px] text-dimmer">
                {serverless
                  ? status.pairing
                    ? `Listening for one device until ${new Date(status.pairing.expires).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}.`
                    : "Listening for one device."
                  : "Good for one device, for an hour."}
              </span>
              <Button
                variant={copied ? "default" : "primary"}
                icon={copied ? <Icon.Check /> : <Icon.Copy />}
                onClick={() => copy(command)}
              >
                {copied ? "Copied" : "Copy"}
              </Button>
            </div>
          </Step>
        </div>
      )}
      <div className="mt-5 flex justify-end">
        <Button onClick={onClose}>{token || failed || !canMint ? "Done" : "Cancel"}</Button>
      </div>
    </Modal>
  );
}

function Step({ n, children }: { n: number; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
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
