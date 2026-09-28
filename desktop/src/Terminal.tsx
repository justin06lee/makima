import { useEffect, useState } from "react";
import { api, type Terminal } from "./api";
import { Modal, Row, toast } from "./ui";
import { Icon } from "./icons";

/// Where the choice of terminal is remembered.
export const TERMINAL = "makima:terminal";

/// The terminals on this device, most wanted first; null until known.
export function useTerminals(): Terminal[] | null {
  const [list, setList] = useState<Terminal[] | null>(null);
  useEffect(() => {
    api.terminals().then(setList).catch(() => setList([]));
  }, []);
  return list;
}

/// A terminal's own app icon, or a plain one while it loads or if it has
/// none. The icons are the one thing in the window allowed to be coloured.
export function TerminalIcon({ id, size = 40 }: { id: string; size?: number }) {
  const [src, setSrc] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    api.terminalIcon(id).then((u) => live && setSrc(u));
    return () => {
      live = false;
    };
  }, [id]);
  if (src) return <img src={src} alt="" draggable={false} style={{ width: size, height: size }} className="shrink-0 object-contain" />;
  // Drawn at the size a real icon's artwork has inside its canvas (Apple's
  // grid leaves a margin), so the plain one lines up with the rest.
  const art = Math.round(size * 0.8);
  return (
    <span style={{ width: size, height: size }} className="flex shrink-0 items-center justify-center">
      <span style={{ width: art, height: art }} className="flex items-center justify-center rounded-[22%] bg-primary text-primary-ink">
        <Icon.Terminal size={Math.round(art * 0.5)} />
      </span>
    </span>
  );
}

/// The SSH button: a new window of the person's terminal running `makima ssh
/// NAME`. The first time there is more than one terminal to choose from, it
/// asks which; after that it just opens. Anything that goes wrong is said at
/// the bottom of the window, wherever the button was.
export function useSSH() {
  const [choosing, setChoosing] = useState<{ peer: string; list: Terminal[] } | null>(null);

  async function open(terminal: string, peer: string) {
    try {
      await api.openSSH(terminal, peer);
      toast(`Opening a shell on ${peer}`);
    } catch (e) {
      toast(String(e), "error");
    }
  }

  async function ssh(peer: string) {
    let list: Terminal[];
    try {
      list = await api.terminals();
    } catch (e) {
      toast(String(e), "error");
      return;
    }
    if (list.length === 0) {
      toast("No terminal app was found on this device.", "error");
      return;
    }
    const saved = localStorage.getItem(TERMINAL);
    if (saved && list.some((t) => t.id === saved)) return open(saved, peer);
    if (list.length === 1) return open(list[0].id, peer);
    setChoosing({ peer, list });
  }

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

  return { ssh, picker };
}

function TerminalPicker({ peer, list, onPick, onClose }: { peer: string; list: Terminal[]; onPick: (t: Terminal) => void; onClose: () => void }) {
  return (
    <Modal title={`Open ${peer} in…`} sub="makima remembers the one you pick. Change it any time in Settings." onClose={onClose} width="max-w-[440px]">
      <div className="grid grid-cols-3 gap-2">
        {list.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => onPick(t)}
            className="group flex flex-col items-center gap-2.5 rounded-xl border border-line bg-panel px-3 pb-3 pt-4 transition hover:border-line-2 hover:bg-sunken active:scale-[0.98]"
          >
            <TerminalIcon id={t.id} size={44} />
            <span className="text-center">
              <span className="block text-[12.5px] font-medium text-ink">{t.name}</span>
              <span className="block text-[11px] text-dimmer">{t.builtin ? "Built in" : " "}</span>
            </span>
          </button>
        ))}
      </div>
    </Modal>
  );
}

/// The same choice, in Settings, for changing it later.
export function TerminalSetting() {
  const list = useTerminals();
  const [chosen, setChosen] = useState(() => localStorage.getItem(TERMINAL) ?? "");

  function change(id: string) {
    if (id) localStorage.setItem(TERMINAL, id);
    else localStorage.removeItem(TERMINAL);
    setChosen(id);
  }

  return (
    <Row
      value="Terminal"
      caption="Where SSH opens a shell"
      right={<Select value={chosen} onChange={change} disabled={!list} label="Terminal" options={[{ value: "", label: "Ask the first time" }, ...(list ?? []).map((t) => ({ value: t.id, label: t.name }))]} />}
    />
  );
}

export function Select({
  value,
  onChange,
  options,
  disabled,
  label,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  disabled?: boolean;
  label: string;
}) {
  return (
    <span className="relative inline-flex">
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        aria-label={label}
        className="h-7 appearance-none rounded-[7px] border border-line-2 bg-panel pl-2.5 pr-7 text-[12.5px] text-ink outline-none transition-colors hover:bg-sunken"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <Icon.ChevronDown size={13} className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-dim" />
    </span>
  );
}
