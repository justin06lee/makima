import { useEffect, useRef, useState } from "react";
import { inTauri } from "./api";

/// Files dragged onto the window, and the device they are over.
///
/// The platform's drag events, not the browser's: Tauri hands over real
/// paths, which is what the CLI needs, and it fires them for the whole window
/// rather than one element, with where the pointer is. So anything marked
/// with `data-drop-peer="NAME"` — a device on the map, a row in the list, the
/// drop zone in a device's panel — is a target, and the file goes to whichever
/// one it is let go over. Nobody has to aim at a small box.
///
/// In a plain browser (the development preview) the browser's own drag events
/// stand in, with the file's name as its path, so the interface can be tried.
///
/// Returns whether a drag is in progress and which device it is over.
export function useFileDrop(onDrop: ((peer: string, paths: string[]) => void) | null): { dragging: boolean; over: string | null } {
  const [dragging, setDragging] = useState(false);
  const [over, setOver] = useState<string | null>(null);
  const handler = useRef(onDrop);
  handler.current = onDrop;

  useEffect(() => {
    const target = (x: number, y: number): string | null => {
      const el = document.elementFromPoint(x, y)?.closest("[data-drop-peer]");
      const name = el?.getAttribute("data-drop-peer");
      return name && el?.getAttribute("data-drop-disabled") !== "true" ? name : null;
    };

    if (inTauri) {
      let unlisten: (() => void) | undefined;
      let gone = false;
      (async () => {
        const { getCurrentWebview } = await import("@tauri-apps/api/webview");
        const un = await getCurrentWebview().onDragDropEvent((e) => {
          if (!handler.current) return;
          const p = e.payload;
          // Positions arrive in physical pixels; the page is laid out in CSS ones.
          const at = "position" in p ? target(p.position.x / devicePixelRatio, p.position.y / devicePixelRatio) : null;
          switch (p.type) {
            case "enter":
            case "over":
              setDragging(true);
              setOver(at);
              break;
            case "leave":
              setDragging(false);
              setOver(null);
              break;
            case "drop":
              setDragging(false);
              setOver(null);
              if (at && p.paths.length > 0) handler.current(at, p.paths);
              break;
          }
        });
        if (gone) un();
        else unlisten = un;
      })();
      return () => {
        gone = true;
        unlisten?.();
      };
    }

    let depth = 0;
    const onEnter = (e: DragEvent) => {
      if (!handler.current || !e.dataTransfer?.types.includes("Files")) return;
      depth++;
      setDragging(true);
    };
    const onOver = (e: DragEvent) => {
      if (!handler.current || !e.dataTransfer?.types.includes("Files")) return;
      e.preventDefault();
      setOver(target(e.clientX, e.clientY));
    };
    const onLeave = () => {
      depth = Math.max(0, depth - 1);
      if (depth === 0) {
        setDragging(false);
        setOver(null);
      }
    };
    const onDropEv = (e: DragEvent) => {
      e.preventDefault();
      depth = 0;
      setDragging(false);
      setOver(null);
      const at = target(e.clientX, e.clientY);
      const files = Array.from(e.dataTransfer?.files ?? []).map((f) => `/Users/you/Desktop/${f.name}`);
      if (at && files.length && handler.current) handler.current(at, files);
    };
    window.addEventListener("dragenter", onEnter);
    window.addEventListener("dragover", onOver);
    window.addEventListener("dragleave", onLeave);
    window.addEventListener("drop", onDropEv);
    return () => {
      window.removeEventListener("dragenter", onEnter);
      window.removeEventListener("dragover", onOver);
      window.removeEventListener("dragleave", onLeave);
      window.removeEventListener("drop", onDropEv);
    };
  }, []);

  return { dragging: dragging && !!onDrop, over: onDrop ? over : null };
}
