import { useEffect, useRef, useState } from "react";
import { inTauri } from "./api";

/// Files dragged onto the window.
///
/// The platform's drag events, not the browser's: Tauri hands over real
/// paths, which is what the CLI needs, and it fires them for the whole window
/// rather than one element. So the pointer is hit-tested here: anything
/// marked `data-drop-peer="NAME"` under it is where the files go, and with
/// nothing under it they go to `fallback` — the device open in the inspector
/// — so nobody has to aim.
///
/// Returns whether a drag is in progress and which device it is over.
/// Passing null disables it.
export function useDrop(
  onFiles: ((paths: string[], peer: string) => void) | null,
  fallback: string | null,
): { dragging: boolean; over: string | null } {
  const [dragging, setDragging] = useState(false);
  const [over, setOver] = useState<string | null>(null);
  const handler = useRef(onFiles);
  handler.current = onFiles;
  const fb = useRef(fallback);
  fb.current = fallback;

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let gone = false;

    if (!inTauri) return;

    // Tauri reports physical pixels; the DOM works in CSS ones.
    const target = (p: { x: number; y: number }): string | null => {
      const r = window.devicePixelRatio || 1;
      const el = document.elementFromPoint(p.x / r, p.y / r)?.closest<HTMLElement>("[data-drop-peer]");
      return el?.dataset.dropPeer || fb.current;
    };

    (async () => {
      const { getCurrentWebview } = await import("@tauri-apps/api/webview");
      const un = await getCurrentWebview().onDragDropEvent((e) => {
        if (!handler.current) return;
        switch (e.payload.type) {
          case "enter":
          case "over":
            setDragging(true);
            setOver(target(e.payload.position));
            break;
          case "leave":
            setDragging(false);
            setOver(null);
            break;
          case "drop": {
            setDragging(false);
            setOver(null);
            const peer = target(e.payload.position);
            if (peer && e.payload.paths.length > 0) handler.current(e.payload.paths, peer);
            break;
          }
        }
      });
      if (gone) un();
      else unlisten = un;
    })();

    return () => {
      gone = true;
      unlisten?.();
    };
  }, []);

  return { dragging: dragging && !!onFiles, over: dragging && onFiles ? over : null };
}
