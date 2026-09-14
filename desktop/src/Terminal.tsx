import { useEffect, useState } from "react";
import { api, type Terminal } from "./api";
import { Card, Modal, Row } from "./ui";
import { Icon } from "./icons";

/// Where the choice of terminal is remembered.
const TERMINAL = "makima:terminal";

/// The SSH button: a new window of the person's terminal running `makima ssh
/// NAME`. The first time there is more than one terminal to choose from, it
/// asks which; after that it just opens.
export function useSSH() {
  const [choosing, setChoosing] = useState<{ peer: string; list: Terminal[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function open(terminal: string, peer: string) {
    setError(null);
    try {
      await api.openSSH(terminal, peer);
    } catch (e) {
      setError(String(e));
    }
  }

  async function ssh(peer: string) {
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
  }

  const picker = choosing && (
    <TerminalPicker
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

function TerminalPicker({ list, onPick, onClose }: { list: Terminal[]; onPick: (t: Terminal) => void; onClose: () => void }) {
  return (
    <Modal title="Open SSH in" onClose={onClose}>
      <p className="mb-3 text-[13px] leading-relaxed text-dim">
        These are the terminals on this device. makima remembers the one you pick — change it in Settings.
      </p>
      <Card>
        {list.map((t) => (
          <Row
            key={t.id}
            value={t.name}
            caption={t.builtin ? "Comes with the system" : undefined}
            right={<Icon.Terminal className="text-dim" />}
            onClick={() => onPick(t)}
          />
        ))}
      </Card>
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
      value="Terminal"
      caption="Where the SSH button opens a shell"
      right={
        <select
          value={chosen}
          onChange={(e) => change(e.target.value)}
          disabled={!list}
          aria-label="Terminal"
          className="h-7 rounded-md border border-line-2 bg-bg px-2 text-[12.5px] text-ink outline-none focus:border-accent"
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
