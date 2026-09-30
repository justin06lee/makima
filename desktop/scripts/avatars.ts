// Fetch and crop the device pictures into src/avatars/, once.
//
// Run by `bun run build`, `bun run dev` and the Makefile's app targets. Each
// picture already there is left alone, so after the first build this does
// nothing. It never fails the build: offline, or off a Mac (the cropping is
// sips), it says so and the app falls back to initials. See src/characters.ts
// for why these are not simply committed.

import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CHARACTERS } from "../src/characters.ts";

const OUT = join(import.meta.dir, "..", "src", "avatars");
const SIZE = 256;
// Grey, so a panel with a touch of colour on it — a coloured page, a red
// stamp — comes out as black and white as the rest.
const GRAY = "/System/Library/ColorSync/Profiles/Generic Gray Gamma 2.2 Profile.icc";

// Each picture remembers the crop it was made with, so changing a source or
// a crop in characters.ts remakes just that one on the next build.
const stamp = (c: (typeof CHARACTERS)[number]) => `${c.url}#${c.crop.join(",")}`;
const STAMPS = join(OUT, "sources.json");
const made: Record<string, string> = existsSync(STAMPS) ? JSON.parse(readFileSync(STAMPS, "utf8")) : {};

const missing = CHARACTERS.filter((c) => !existsSync(join(OUT, `${c.id}.jpg`)) || made[c.id] !== stamp(c));
if (missing.length === 0) process.exit(0);

if (process.platform !== "darwin") {
  console.log(`  avatars skipped: cropping needs sips (macOS); devices will show their initials`);
  process.exit(0);
}

mkdirSync(OUT, { recursive: true });

function sips(args: string[]): string {
  const r = Bun.spawnSync(["sips", ...args], { stderr: "pipe" });
  if (r.exitCode !== 0) throw new Error(`sips ${args.join(" ")}: ${r.stderr.toString().trim()}`);
  return r.stdout.toString();
}

let count = 0;
for (const c of missing) {
  const src = join(tmpdir(), `makima-avatar-${c.id}.png`);
  const cut = join(tmpdir(), `makima-avatar-${c.id}-cut.png`);
  try {
    // format=original: the wiki otherwise answers with WebP, which sips reads
    // on some macOS versions and not others.
    const res = await fetch(`${c.url}&format=original`, { headers: { "User-Agent": "makima-desktop-build" } });
    if (!res.ok) throw new Error(`${res.status} from the wiki`);
    writeFileSync(src, new Uint8Array(await res.arrayBuffer()));

    const dims = sips(["-g", "pixelWidth", "-g", "pixelHeight", src]).match(/pixelWidth: (\d+)\s+pixelHeight: (\d+)/);
    if (!dims) throw new Error("could not read its size");
    const [w, h] = [Number(dims[1]), Number(dims[2])];
    const [cx, cy, s] = c.crop;
    const side = Math.min(Math.round(s * h), w, h);
    const x = Math.max(0, Math.min(w - side, Math.round(cx * w - side / 2)));
    const y = Math.max(0, Math.min(h - side, Math.round(cy * h - side / 2)));

    sips(["-c", String(side), String(side), "--cropOffset", String(y), String(x), src, "--out", cut]);
    sips(["-z", String(SIZE), String(SIZE), "-m", GRAY, "-s", "format", "jpeg", "-s", "formatOptions", "86", cut, "--out", join(OUT, `${c.id}.jpg`)]);
    made[c.id] = stamp(c);
    count++;
  } catch (e) {
    console.log(`  avatar  ${c.id}: ${e instanceof Error ? e.message : e}`);
  } finally {
    rmSync(src, { force: true });
    rmSync(cut, { force: true });
  }
}
// A face no longer in the list goes too, so the picker never offers it.
const known = new Set(CHARACTERS.map((c) => `${c.id}.jpg`));
for (const f of readdirSync(OUT)) if (f.endsWith(".jpg") && !known.has(f)) rmSync(join(OUT, f));
writeFileSync(STAMPS, JSON.stringify(made, null, 1));
console.log(`  avatars ${count} of ${missing.length} fetched into src/avatars/`);
