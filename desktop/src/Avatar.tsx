import { useRef, useState } from "react";
import { FACES, labelOf, pictureOf, pictureURL, setPref, squareJPEG, usePrefs } from "./prefs";
import { Button, Input, Modal, toast } from "./ui";
import { Icon } from "./icons";

/// A device's picture, or its initial. Offline, it fades back and flattens:
/// the faces are already black and white, so being out of reach has to show
/// as the ink going pale rather than as colour going grey.
export function Avatar({ name, size = 28, offline, className = "" }: { name: string; size?: number; offline?: boolean; className?: string }) {
  const prefs = usePrefs();
  return <Picture src={pictureOf(prefs, name)} label={labelOf(prefs, name)} size={size} offline={offline} className={className} />;
}

function Picture({ src, label, size, offline, className = "" }: { src: string | null; label: string; size: number; offline?: boolean; className?: string }) {
  const style = { width: size, height: size };
  if (src) {
    return (
      <span
        className={`relative inline-block shrink-0 overflow-hidden rounded-full bg-active transition-[filter,opacity] duration-300 ${offline ? "opacity-40 contrast-[0.7]" : ""} ${className}`}
        style={style}
      >
        <img src={src} alt="" draggable={false} className="size-full object-cover" />
        <span className="pointer-events-none absolute inset-0 rounded-full shadow-[inset_0_0_0_1px_rgba(0,0,0,0.08)]" />
      </span>
    );
  }
  return (
    <span
      className={`inline-flex shrink-0 items-center justify-center rounded-full bg-active font-semibold uppercase text-ink-2 ${offline ? "opacity-40" : ""} ${className}`}
      style={{ ...style, fontSize: Math.max(10, Math.round(size * 0.4)) }}
    >
      {label.trim()[0] ?? "?"}
    </span>
  );
}

/// A picture filling its tile, inset from the ring drawn round a chosen one.
const FILL = "absolute left-[3px] top-[3px] h-[calc(100%-6px)] w-[calc(100%-6px)] rounded-full object-cover";

/// Rename a device and choose its picture — for this app only.
export function DeviceEditor({ name, onClose }: { name: string; onClose: () => void }) {
  const prefs = usePrefs();
  const [label, setLabel] = useState(prefs[name]?.label ?? "");
  const [picture, setPicture] = useState(prefs[name]?.picture ?? "none");
  const file = useRef<HTMLInputElement>(null);
  const uploaded = picture.startsWith("data:") ? picture : prefs[name]?.picture?.startsWith("data:") ? prefs[name]!.picture! : null;

  function save() {
    setPref(name, { label: label.trim() || undefined, picture });
    toast(`Saved ${label.trim() || name}`);
    onClose();
  }

  async function upload(f: File | undefined) {
    if (!f) return;
    try {
      setPicture(await squareJPEG(f));
    } catch {
      toast("That file isn't an image makima can read", "error");
    }
  }

  const shown = label.trim() || name;

  return (
    <Modal
      title="Edit device"
      onClose={onClose}
      width="max-w-[480px]"
      footer={
        <>
          <span className="mr-auto text-[11.5px] text-dimmer">Only this app sees these.</span>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save}>
            Save
          </Button>
        </>
      }
    >
      <div className="flex items-center gap-4">
        <Picture src={pictureURL(picture)} label={shown} size={64} />
        <div className="min-w-0 flex-1">
          <label className="mb-1.5 block text-[12px] text-dim">
            Name
          </label>
          <Input value={label} onChange={setLabel} placeholder={name} onEnter={save} autoFocus />
          <p className="mt-1.5 text-[11.5px] text-dimmer">
            SSH and addresses still use <span className="font-mono text-dim">{name}</span>.
          </p>
        </div>
      </div>

      <div className="mt-6">
        <div className="mb-2.5 flex items-baseline justify-between">
          <h3 className="text-[12.5px] font-medium">Picture</h3>
          {picture !== "none" && (
            <button type="button" onClick={() => setPicture("none")} className="text-[12px] text-dim hover:text-ink">
              Use initial
            </button>
          )}
        </div>
        {/* Each tile is a square cell with the button laid over it. WebKit
            (the Mac app) sizes a square button in a grid by its content, which
            drew the faces as ovals; a cell with nothing in its flow can't be. */}
        <div className="grid grid-cols-7 gap-2">
          <div className="relative aspect-square">
            <button
              type="button"
              onClick={() => file.current?.click()}
              title="Upload a picture"
              className={`absolute inset-0 flex items-center justify-center rounded-full border border-dashed transition-colors hover:border-dim hover:text-ink
                ${uploaded && picture === uploaded ? "border-ink text-ink" : "border-line-2 text-dim"}`}
            >
              {uploaded ? (
                <img src={uploaded} alt="" className={`${FILL} ${picture === uploaded ? "" : "opacity-80"}`} />
              ) : (
                <Icon.Upload size={16} />
              )}
            </button>
          </div>
          {FACES.map((f) => {
            const on = picture === `face:${f.id}`;
            return (
              <div key={f.id} className="relative aspect-square">
                <button
                  type="button"
                  onClick={() => setPicture(`face:${f.id}`)}
                  title={f.name}
                  aria-label={f.name}
                  aria-pressed={on}
                  className={`group absolute inset-0 rounded-full transition ${on ? "shadow-[0_0_0_2px_var(--ink)]" : "hover:shadow-[0_0_0_2px_var(--line-2)]"}`}
                >
                  <img src={f.url} alt="" draggable={false} className={`${FILL} transition-transform group-hover:scale-[1.04]`} />
                </button>
              </div>
            );
          })}
        </div>
        {FACES.length === 0 && (
          <p className="mt-3 text-[12px] leading-relaxed text-dim">The built-in pictures weren't fetched when this app was built. Upload one of your own.</p>
        )}
        <input ref={file} type="file" accept="image/*" className="hidden" onChange={(e) => upload(e.target.files?.[0])} />
      </div>
    </Modal>
  );
}
