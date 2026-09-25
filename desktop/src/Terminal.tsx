import { useCallback, useEffect, useState } from "react";
import { api, type Terminal } from "./api";
import { Modal, Row } from "./ui";
import { Icon } from "./icons";

/// Where the choice of terminal is remembered.
const TERMINAL = "makima:terminal";

/// The SSH button: a new window of the person's terminal running `makima ssh
/// NAME`. The first time there is more than one terminal to choose from, it
/// asks which; after that it just opens.
export function useSSH() {
  const [choosing, setChoosing] = useState<{ peer: string; list: Terminal[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const open = useCallback(async (terminal: string, peer: string) => {
    setError(null);
    try {
      await api.openSSH(terminal, peer);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  const ssh = useCallback(
    async (peer: string) => {
      setError(null);
      let list: Terminal[];
      try {
        list = await api.terminals();
      } catch (e) {
        setError(String(e));
        return;
      }
      if (list.length === 0) {
        setError("No terminal app was found on this device.");
        return;
      }
      const saved = localStorage.getItem(TERMINAL);
      if (saved && list.some((t) => t.id === saved)) return open(saved, peer);
      if (list.length === 1) return open(list[0].id, peer);
      setChoosing({ peer, list });
    },
    [open],
  );

  const picker = choosing && (
    <TerminalPicker
      peer={choosing.peer}
      list={choosing.list}
      onClose={() => setChoosing(null)}
      onPick={(t) => {
        localStorage.setItem(TERMINAL, t.id);
        setChoosing(null);
        void open(t.id, choosing.peer);
      }}
    />
  );

  return { ssh, picker, error };
}

function TerminalPicker({ peer, list, onPick, onClose }: { peer: string; list: Terminal[]; onPick: (t: Terminal) => void; onClose: () => void }) {
  return (
    <Modal title={`Open ${peer} in…`} subtitle="makima remembers the one you pick. Change it in Settings." onClose={onClose}>
      <div className="grid grid-cols-2 gap-2">
        {list.map((t, i) => (
          <button
            key={t.id}
            type="button"
            autoFocus={i === 0}
            onClick={() => onPick(t)}
            className="flex items-center gap-3 rounded-xl bg-raised px-3.5 py-3 text-left shadow-[var(--shadow-sm)] transition hover:bg-raised-2 active:translate-y-px"
          >
            <span className="flex size-9 items-center justify-center rounded-lg bg-ink text-bg">
              <Icon.Terminal size={16} />
            </span>
            <span className="min-w-0">
              <span className="block truncate text-[13.5px] font-medium">{t.name}</span>
              <span className="block text-[11.5px] text-dim">{t.builtin ? "Comes with the system" : "Installed"}</span>
            </span>
          </button>
        ))}
      </div>
    </Modal>
  );
}

/// The same choice, in Settings, for changing it later.
export function TerminalSetting() {
  const [list, setList] = useState<Terminal[] | null>(null);
  const [chosen, setChosen] = useState(() => localStorage.getItem(TERMINAL) ?? "");

  useEffect(() => {
    api.terminals().then(setList).catch(() => setList([]));
  }, []);

  function change(id: string) {
    if (id) localStorage.setItem(TERMINAL, id);
    else localStorage.removeItem(TERMINAL);
    setChosen(id);
  }

  return (
    <Row
      icon={<Icon.Terminal />}
      value="Terminal"
      caption="Where SSH opens a shell"
      right={
        <select
          value={chosen}
          onChange={(e) => change(e.target.value)}
          disabled={!list}
          aria-label="Terminal"
          className="h-[26px] rounded-md border border-line-2 bg-raised px-2 text-[12.5px] text-ink outline-none focus:border-accent"
        >
          <option value="">Ask the first time</option>
          {list?.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name}
            </option>
          ))}
        </select>
      }
    />
  );
}
