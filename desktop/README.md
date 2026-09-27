# makima desktop

A menu bar item and a window over the daemon's local API, so that "which of my
machines can I see right now" stops being a question you have to type a command
to answer — and so that setting makima up is two buttons rather than two
commands.

Tauri rather than Electron: the same app in ~10 MB instead of ~150 MB, using
the system web view that is already running on both platforms. macOS and Linux.

## Running it

```sh
make app        # build it, put it in /Applications (or install the .deb/.rpm/AppImage), open it
make app-dev    # develop against a pretend mesh, no root and no tunnel
```

`make` on its own does the same whenever Rust and bun are present, so the app
on the machine is never older than the code. Both keep the machine's state —
the network, its keys, the app's settings — and only quit the app, replace it,
and start it again. Both build the four Go binaries first and drop them in
`src-tauri/binaries/`, named for the target triple, which is how Tauri bundles
"sidecars". The app runs the `makima` beside its own executable, so a
downloaded bundle works with nothing else installed.

macOS ties a privacy grant to the binary that was granted it, so each install
resets this app's own grants (`tccutil reset All sh.makima.desktop`) and the
app asks again rather than inheriting an entry that looks enabled and is not.

`make app-dev` needs a status server to talk to, in another terminal:

```sh
go run ./desktop/devserver
```

That serves `localapi.Status` — the daemon's own types, not a hand-written JSON
blob — so a field that changes shape in Go breaks the app too, and the
interface is never developed against a fiction. Two environment variables
steer the app while developing: `MAKIMA_GUI_SOCKET` points it at the pretend
socket, and `MAKIMA_DEV_MEMBER=1` makes it believe this machine is already on
a network, which is how to see the "off" screen without an `/etc/makima`.

The interface also runs in a plain browser, with no Tauri at all: with the
devserver up, `bun run dev` in `desktop/` and open http://localhost:5183. The
devserver answers over TCP too and vite proxies to it; anything the CLI would
do is pretended. The query string picks what to look at — `?state=setup`,
`?state=off`, `?page=services|exit|settings`, `?select=tenet` (or `self`),
`?exit=tenet`, `?dark=1`, `?tailscale=0`, `?holds=0`.

## What it shows

**The menu bar** is most of the app: connected or not, this device's address,
every other device with a dot for whether it is reachable (click to copy the
address), the exit node as a radio group, and Connect/Disconnect. It is a
native menu, rebuilt only when what it shows changes.

**The window** is drawn in makima's own colours — graphite and paper, and one
vermilion for whatever is live — with Instrument Sans for the interface and
JetBrains Mono for every address, bundled because the webview loads nothing
from elsewhere. It has three pages and Settings:

- *Mesh* is the network as rings round this device — direct, relayed, offline
  — with the same devices as a list a click away. Selecting one opens a panel:
  latency and its recent history, addresses to copy, SSH, Ping, services with
  Open buttons, and a drop target. Files dropped on any device in the map or
  the list go to that device's inbox.
- *Services* is every service on the network as cards, and what this device
  shares, with Share and Remove.
- *Exit node* draws this device → the exit → the internet, and picks one.
- *Settings* has the login item, the terminal, the command-line install,
  diagnostics, the keyboard shortcuts, and the network's particulars.

⌘K opens a palette over all of it — devices, services, actions and pages.
⌘1–⌘3 switch pages, ⌘N adds a device, ↑/↓ walk the map, Escape closes a panel.

**The first run** has no daemon and no configuration, so it asks the one
question that matters: start a network, or join one by typing the fifteen
words the first device shows (or pasting its invite). `makima up` registers the
daemon with launchd or systemd, so from then on the device is connected
whenever it is on, and the app becomes a login item so the menu bar is there
too; Disconnect takes the registration away, and Settings turns the login item
off.

**About the password.** Saying yes once writes a sudoers rule so Connect,
Disconnect and the read-only commands stop asking — the buttons pressed daily.
It deliberately does not cover anything that changes who this device trusts:
joining a network, adding a device, choosing an exit node and moving off
Tailscale ask every time. A standing grant for those would let anything else
running as you put this machine on a network of its choosing without a prompt,
since an invite carries the control plane it points at. Delete
`/etc/sudoers.d/makima_<you>` to make everything ask again.

**Move from Tailscale** appears when Tailscale is running here — on the first
run beside the two cards, over the device list, and in Settings. It is a
full-window sheet over `makima migrate`: *Look* lists every device on the
tailnet as it is examined over SSH (with an Approve button when Tailscale SSH
wants a browser check), *Choose* picks the Control Devil and what comes along
(and takes sudo passwords for devices that need one), and *Move* follows each
device to the end: makima on it, your SSH keys, joined beside Tailscale,
reached over makima, and — if *Uninstall Tailscale* is on — Tailscale removed.
Each ends *moved*, *both*, or *stayed*. The CLI runs as you, so it has your SSH keys; the
steps on this device that need root come back up to the app and go through the
same prompt as every other button.

## How it talks to the daemon

Two channels, deliberately unequal.

**Reading** goes over `makimad-gui.sock`, a second Unix socket the daemon opens
beside its own. It is read-only by construction — `localapi.NewServer(n,
false)` — and `chown`ed to whoever brought the tunnel up, so exactly one
account can reach it and nothing sent down it can change anything. That is what
makes it safe for a window rendering HTML to hold open.

**Writing** does not go over a socket at all. Every action runs the `makima`
CLI behind the platform's own authentication dialog — Authorization Services on
macOS, polkit on Linux. Changing an exit node crosses exactly the same
permission boundary as typing `sudo`, made visible instead of implicit. A web
view cannot reconfigure a VPN by accident, because the web view was never able
to.

The set of privileged operations is an enum in `src-tauri/src/privileged.rs`,
not a command string. The UI can name one of them; it cannot compose a new one.
The one thing that runs *without* a prompt is `makima cp`, for the drop zone:
it needs no root, and the daemon answers it over the read-only socket.

On macOS the admin prompt's shell carries none of the variables sudo would, so
the app tells the daemon who it is running for with `MAKIMA_OWNER`; on Linux,
pkexec sets `PKEXEC_UID` itself. Either way the daemon knows whose socket to
open and whose Downloads to put files in.

## Building on Linux

Tauri uses the system web view, so it needs the GTK and WebKit development
packages:

```sh
# Arch
sudo pacman -S webkit2gtk-4.1 base-devel curl wget file openssl \
               libayatana-appindicator librsvg

# Debian / Ubuntu
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
                 libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
```

`libayatana-appindicator` is what puts the tray icon in the panel. Without it
the app still runs; it just has nowhere to live when its window is closed.

## Layout

```
src/              the interface — React, Tailwind, no router and no state library
src/api.ts        the daemon's types, mirrored, and the invoke wrappers
src/App.tsx       the title bar, the pages, the shortcuts, and which screen is showing
src/style.css     the palette, light and dark, the fonts, and the motion
src/ui.tsx        the pieces every screen is built from
src/Iris.tsx      the ringed iris: the status light, the splash, the empty screens
src/Setup.tsx     the first run: start a network, or join one
src/Mesh.tsx      the map and the list of devices, and where dropped files go
src/Device.tsx    the panel for one device, or for this one
src/Services.tsx  every service on the network, and what this device shares
src/ExitNodes.tsx pick an exit node, with the route drawn
src/Palette.tsx   ⌘K
src/toast.tsx     the small confirmations at the foot of the window
src/Settings.tsx  login item, CLI install, diagnostics
src/AddDevice.tsx the invite sheet
src/Migrate.tsx   moving from Tailscale: look, choose the Control Devil, move
src-tauri/        the Rust half
  daemon.rs       reading status over the read-only socket, and the facts on disk
  privileged.rs   the named actions, and the auth prompt in front of them
  migrate.rs      runs `makima migrate`, streams it to the window, answers its root steps
  tray.rs         the menu bar, rebuilt from the snapshot when it changes
  lib.rs          the window, the plugins, and what closing the window means
  binaries/       the four Go binaries, built by `make sidecars`
  kits/           the same four for every other platform, built by `make kits`
devserver/        a pretend mesh, for working on the UI without root
```

## Icons

The app icon is a greyscale drawing of Makima, cropped in close on one eye so
its ringed iris fills a macOS app tile (Apple's 824px grid in a 1024px canvas,
185.4px corners). The tile shape matters: macOS boxes any other shape in a grey
frame. The menu bar and in-app mark use a simplified monochrome iris; macOS
tints the menu bar template automatically, and the existing disconnected state
dims it.

The sources are `src-tauri/icons/icon-source.png` (the finished 1024px tile)
and `src-tauri/icons/tray.svg`. After changing either, run from `desktop/`:

```sh
bun run tauri icon src-tauri/icons/icon-source.png --output /tmp/makima-icons
for icon in 32x32.png 128x128.png 128x128@2x.png icon.png icon.icns icon.ico; do
  cp "/tmp/makima-icons/$icon" src-tauri/icons/
done
rsvg-convert src-tauri/icons/tray.svg -o src-tauri/icons/tray.png
```

Keep `Icon.Mark` in `src/icons.tsx` aligned with the tray SVG. The SVGs have
no gradients, shadows, or reflections. Generated desktop assets are checked
in, so normal builds do not need `rsvg-convert`.
