import { useEffect, useRef, useState } from "react";
import { inTauri } from "./api";

/// Files dragged onto the window.
///
/// The platform's drag events, not the browser's: Tauri hands over real
/// paths, which is what the CLI needs, and it fires them for the whole window
/// rather than one element. So while a device is selected, the whole window
/// is its drop target and the zone merely lights up to say so — nobody has to
/// aim.
///
/// Returns whether a drag is in progress. Passing null disables it.
export function useDrop(onFiles: ((paths: string[]) => void) | null): boolean {
  const [dragging, setDragging] = useState(false);
  const handler = useRef(onFiles);
  handler.current = onFiles;

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let gone = false;

    if (!inTauri) return;
    (async () => {
      const { getCurrentWebview } = await import("@tauri-apps/api/webview");
      const un = await getCurrentWebview().onDragDropEvent((e) => {
        if (!handler.current) return;
        switch (e.payload.type) {
          case "enter":
          case "over":
            setDragging(true);
            break;
          case "leave":
            setDragging(false);
            break;
          case "drop":
            setDragging(false);
            if (e.payload.paths.length > 0) handler.current(e.payload.paths);
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
  }, []);

  return dragging && !!onFiles;
}
