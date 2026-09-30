import { useSyncExternalStore } from "react";
import { CHARACTERS } from "./characters";

// What this app calls each device, and the picture it wears.
//
// Local to this app, on this machine: renaming a device here changes nothing
// on the network. SSH, the .makima names and the addresses all stay the
// mesh's, because other machines — and every script — know it by those.

const files = import.meta.glob("./avatars/*.jpg", { eager: true, import: "default" }) as Record<string, string>;

export type Face = { id: string; name: string; url: string };

/// The faces that were fetched at build time; empty when none were.
export const FACES: Face[] = CHARACTERS.flatMap((c) => {
  const url = files[`./avatars/${c.id}.jpg`];
  return url ? [{ id: c.id, name: c.name, url }] : [];
});

/// picture is "face:<id>", a data: URL of an uploaded image, or "none".
export type DevicePref = { label?: string; picture?: string };
export type Prefs = Record<string, DevicePref>;

const KEY = "makima:devices";
const listeners = new Set<() => void>();
let prefs: Prefs = load();

function load(): Prefs {
  try {
    const p = JSON.parse(localStorage.getItem(KEY) ?? "{}");
    return p && typeof p === "object" ? p : {};
  } catch {
    return {};
  }
}

function save(next: Prefs) {
  prefs = next;
  try {
    localStorage.setItem(KEY, JSON.stringify(next));
  } catch {
    // Full: uploaded pictures are the only thing big enough to do it. The
    // change still shows until the window closes.
  }
  listeners.forEach((l) => l());
}

export function usePrefs(): Prefs {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => prefs,
  );
}

export function setPref(name: string, patch: DevicePref) {
  save({ ...prefs, [name]: { ...prefs[name], ...patch } });
}

/// The name to show: the one given here, or the device's own.
export function labelOf(p: Prefs, name: string): string {
  return p[name]?.label?.trim() || name;
}

/// The picture a stored value stands for, or null for the initial.
export function pictureURL(picture: string | undefined): string | null {
  if (!picture || picture === "none") return null;
  if (picture.startsWith("face:")) return FACES.find((f) => `face:${f.id}` === picture)?.url ?? null;
  return picture.startsWith("data:image/") ? picture : null;
}

export function pictureOf(p: Prefs, name: string): string | null {
  return pictureURL(p[name]?.picture);
}

function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return h >>> 0;
}

/// Give every device a face the first time this app sees it, so the list is
/// people rather than a column of initials — and keep it, so nobody's face
/// changes when a device joins. Faces already worn are passed over while any
/// are left. The device holding the network is Makima: it is the one every
/// other device answers to.
export function ensurePictures(names: string[], holder: string | null) {
  if (FACES.length === 0) return;
  const missing = names.filter((n) => !prefs[n]?.picture);
  if (missing.length === 0) return;
  const used = new Set(Object.values(prefs).map((p) => p.picture));
  const next = { ...prefs };
  const give = (n: string, f: Face) => {
    used.add(`face:${f.id}`);
    next[n] = { ...next[n], picture: `face:${f.id}` };
  };
  const makima = FACES.find((f) => f.id === "makima");
  if (holder && missing.includes(holder) && makima && !used.has("face:makima")) give(holder, makima);
  for (const n of [...missing].sort()) {
    if (next[n]?.picture) continue;
    const start = hash(n) % FACES.length;
    let pick = FACES[start];
    for (let i = 0; i < FACES.length; i++) {
      const f = FACES[(start + i) % FACES.length];
      if (!used.has(`face:${f.id}`)) {
        pick = f;
        break;
      }
    }
    give(n, pick);
  }
  save(next);
}

/// An uploaded image as a small square JPEG: the middle of it, 256px across,
/// in grey like the built-in faces — the window has no colour in it, and a
/// photo should not be the one thing that does. Stored in localStorage, so
/// it has to be small.
export async function squareJPEG(file: File): Promise<string> {
  const url = URL.createObjectURL(file);
  try {
    const img = new Image();
    img.src = url;
    await img.decode();
    const side = Math.min(img.naturalWidth, img.naturalHeight);
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = 256;
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("no canvas");
    ctx.imageSmoothingQuality = "high";
    ctx.drawImage(img, (img.naturalWidth - side) / 2, (img.naturalHeight - side) / 2, side, side, 0, 0, 256, 256);
    // By hand rather than ctx.filter, which the WebKit on older macOS ignores.
    const px = ctx.getImageData(0, 0, 256, 256);
    const d = px.data;
    for (let i = 0; i < d.length; i += 4) {
      const y = 0.2126 * d[i] + 0.7152 * d[i + 1] + 0.0722 * d[i + 2];
      d[i] = d[i + 1] = d[i + 2] = y;
    }
    ctx.putImageData(px, 0, 0);
    return canvas.toDataURL("image/jpeg", 0.86);
  } finally {
    URL.revokeObjectURL(url);
  }
}
