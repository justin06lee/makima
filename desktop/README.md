# makima desktop

A window and a tray icon over the daemon's local API, so that "which of my
machines can I see right now" stops being a question you have to type a command
to answer.

Tauri rather than Electron: the same app in ~10 MB instead of ~150 MB, using
the system web view that is already running on both platforms. macOS and Linux.

## Running it

```sh
make app        # build a real bundle — .app and .dmg, or .deb/.rpm/.AppImage
make app-dev    # develop against a pretend mesh, no root and no tunnel
```

`make app-dev` needs a status server to talk to, in another terminal:

```sh
go run ./desktop/devserver
```

That serves `localapi.Status` — the daemon's own types, not a hand-written JSON
blob — so a field that changes shape in Go breaks the app too, and the
interface is never developed against a fiction.

## How it talks to the daemon

Two channels, deliberately unequal.

**Reading** goes over `makimad-gui.sock`, a second Unix socket the daemon opens
beside its own. It is read-only by construction — `localapi.NewServer(n,
false)` — and `chown`ed to whoever ran `makima up`, so exactly one account can
reach it and nothing sent down it can change anything. That is what makes it
safe for a window rendering HTML to hold open.

**Writing** does not go over a socket at all. Every action runs the `makima`
CLI behind the platform's own authentication dialog — Authorization Services on
macOS, polkit on Linux. Changing an exit node crosses exactly the same
permission boundary as typing `sudo`, made visible instead of implicit. A web
view cannot reconfigure a VPN by accident, because the web view was never able
to.

The set of privileged operations is an enum in `src-tauri/src/privileged.rs`,
not a command string. The UI can name one of them; it cannot compose a new one.

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
src/            the interface — React, Tailwind, no router and no state library
src/api.ts      the daemon's types, mirrored, and the invoke wrappers
src-tauri/      the Rust half
  daemon.rs     reading status over the read-only socket
  privileged.rs the named actions, and the auth prompt in front of them
  lib.rs        the window, the tray, and what closing the window means
devserver/      a pretend mesh, for working on the UI without root
```
