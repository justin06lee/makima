import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { copyText } from "./api";
import { Icon } from "./icons";

// Small confirmations at the foot of the window: "Copied tenet.makima",
// "Sent notes.txt to tenet". Copying and sending are silent otherwise, and
// without a word back people click twice and wonder which one took.

type Tone = "ok" | "error" | "info";
type Toast = { id: number; text: string; tone: Tone };

const Ctx = createContext<(text: string, tone?: Tone) => void>(() => {});

export function Toaster({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const next = useRef(1);

  const push = useCallback((text: string, tone: Tone = "ok") => {
    const id = next.current++;
    // One of each at a time: pressing Copy three times says it once.
    setToasts((t) => [...t.filter((x) => x.text !== text).slice(-2), { id, text, tone }]);
  }, []);

  return (
    <Ctx.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed inset-x-0 bottom-4 z-[60] flex flex-col items-center gap-2" aria-live="polite">
        {toasts.map((t) => (
          <ToastPill key={t.id} toast={t} onDone={() => setToasts((all) => all.filter((x) => x.id !== t.id))} />
        ))}
      </div>
    </Ctx.Provider>
  );
}

function ToastPill({ toast, onDone }: { toast: Toast; onDone: () => void }) {
  useEffect(() => {
    const t = setTimeout(onDone, toast.tone === "error" ? 5000 : 1800);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const icon =
    toast.tone === "ok" ? <Icon.Check size={14} className="text-green" /> : toast.tone === "error" ? <Icon.Warn size={14} className="text-red" /> : <Icon.Info size={14} className="text-dim" />;
  return (
    <div className="rise pointer-events-auto flex max-w-[520px] items-center gap-2 rounded-full bg-ink py-1.5 pl-3 pr-4 text-[12.5px] font-medium text-bg shadow-[var(--shadow)]">
      {icon}
      <span className="truncate">{toast.text}</span>
    </div>
  );
}

export function useToast() {
  return useContext(Ctx);
}

/// Copy to the clipboard and say so.
export function useCopy() {
  const toast = useToast();
  return useCallback(
    async (text: string, what?: string) => {
      try {
        await copyText(text);
        toast(`Copied ${what ?? text}`);
      } catch (e) {
        toast(`Could not copy: ${String(e)}`, "error");
      }
    },
    [toast],
  );
}
