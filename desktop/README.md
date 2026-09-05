# makima desktop

A menu bar item and a window over the daemon's local API, so that "which of my
machines can I see right now" stops being a question you have to type a command
to answer — and so that setting makima up is two buttons rather than two
commands.

Tauri rather than Electron: the same app in ~10 MB instead of ~150 MB, using
the system web view that is already running on both platforms. macOS and Linux.

## Running it

```sh
make app        # build a real bundle — .app and .dmg, or .deb/.rpm/.AppImage
make app-dev    # develop against a pretend mesh, no root and no tunnel
```

Both build the four Go binaries first and drop them in `src-tauri/binaries/`,
named for the target triple, which is how Tauri bundles "sidecars". The app
runs the `makima` beside its own executable, so a downloaded bundle works with
nothing else installed.

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

## What it shows

**The menu bar** is most of the app: connected or not, this device's address,
every other device with a dot for whether it is reachable (click to copy the
address), the exit node as a radio group, and Connect/Disconnect. It is a
native menu, rebuilt only when what it shows changes.

**The window** has three pages. *Devices* is a list on the left and a detail
pane on the right — addresses to copy, services with Open buttons, SSH, and a
drop zone that sends a file to that device's inbox. *Exit nodes* picks one.
*Settings* has the login item, the command-line install, diagnostics, and the
network's particulars.

**The first run** has no daemon and no configuration, so it asks the one
question that matters: start a network, or join one with a pasted invite.

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
src/App.tsx       the title bar, the sidebar, and which screen is showing
src/Setup.tsx     the first run: start a network, or join one
src/Devices.tsx   the list and the detail pane, including the drop zone
src/ExitNodes.tsx pick an exit node
src/Settings.tsx  login item, CLI install, diagnostics
src/AddDevice.tsx the invite sheet
src-tauri/        the Rust half
  daemon.rs       reading status over the read-only socket, and the facts on disk
  privileged.rs   the named actions, and the auth prompt in front of them
  tray.rs         the menu bar, rebuilt from the snapshot when it changes
  lib.rs          the window, the plugins, and what closing the window means
  binaries/       the four Go binaries, built by `make sidecars`
devserver/        a pretend mesh, for working on the UI without root
```
