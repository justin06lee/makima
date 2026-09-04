<div align="center">

<img src="assets/makima.svg" alt="makima" width="440" />

# makima

**A mesh network you own end to end.**<br>
*Every machine you have on one flat address space — no accounts, no third party, no coordination server but your own.*

</div>

---

makima is a WireGuard mesh with its own control plane. You run the coordination
server, you run the relay, and no packet or key ever touches infrastructure you
do not administer.

It is built the way Tailscale is built, because that architecture is right: a
central service that decides *who may talk to whom*, and direct encrypted paths
that carry the traffic without passing through it. The banner above is the whole
design — gold chains from the centre to every node, crimson paths straight
between them.

## Status

**Feature-complete.** `makima up` on one machine makes a mesh; one pasted
invite puts another on it. A node is handed an address and receives the mesh's
membership over a long poll that pushes changes as they happen. Local services
are published on the mesh — automatically, as they start — without being
exposed to the LAN, the host firewall is configured to let tunnel traffic
through, and a web interface shows what is reachable and what is broken.

It reaches its peers directly where it can and through a relay where it
cannot, upgrading to a direct path the moment one is found. Names resolve,
access is governed by policy, subnets and exit nodes route, and a mesh that
turns on the network lock no longer has to trust its own control server about
who belongs.

| | | |
|---|---|---|
| **M0** | TUN + WireGuard, static peers | **done** |
| **M1** | control server, registration, netmap long-poll | **done** |
| **M2** | relay — works from anywhere, no port forwarding | **done** |
| **M3** | disco — STUN, endpoint exchange, hole punching, direct paths | **done** |
| **M4** | port mapping — NAT-PMP and PCP | **done** |
| **M5** | DNS names, ACLs, exit nodes, subnet routes | **done** |
| **M6** | network lock — node-key signing, key rotation | **done** |
| **M7** | one-command setup — `up`, invites, services that publish themselves | **done** |

What this has *not* had is a week of running on real machines behind real NATs.
Every layer is covered by tests, including the relay and the path-selecting
socket end to end, but tests are not the same as a laptop moving between a
café and a home network. See [Known limits](#known-limits).

## Install

```sh
make
```

Builds all four binaries and installs them to `/usr/local/bin`. `make update`
stops a running daemon, replaces the binaries, and leaves you ready to start
again. `make service` installs a systemd unit or launchd plist so the daemon
survives a reboot — kept separate from `make` because a VPN that enables itself
at boot on a machine you were only trying out is a surprise.

Requires Go 1.25 or newer. Linux and macOS today; Windows cross-compiles but
its address assignment is not wired up yet.

## Use

Pick the machine that will hold the mesh together, and run:

```sh
makima up
```

**Pick it deliberately.** Every other machine has to be able to reach this one
to join, so if it is a desktop behind your home NAT, the mesh only works from
inside your house — a laptop in a café cannot join, and once joined can only
find its way home through a relay. `makima up` tells you which of the two you
just did.

If you already self-host something on a public name, you have already solved
this and can reuse it. Whatever carries `something.example.dev` into your
network — a reverse proxy, a Cloudflare tunnel, a port forward — can carry the
coordination plane too. Point it at port 8080 and say so:

```sh
makima up -advertise https://makima.example.dev
```

Otherwise put it on anything with a public address; a small VPS is plenty.

A public machine automatically becomes the relay as well, so machines that
cannot reach each other directly still meet there. Nothing at home needs a port
forwarded either way.

That is the whole thing. There is no mesh yet, so it makes one, puts the
coordination plane on this machine, turns on names, joins itself, starts the
daemon, and prints an invite. It asks for sudo when it needs it rather than
failing with advice about it.

On every machine after, paste what it printed:

```sh
makima join mk1_...
```

One string, because the three things a machine needs to join — where the
coordination plane is, a credential, and the plane's public key — are three
things to get right and one thing to paste. The key travelling *with* the
invite is the point: a node that has to fetch it over the connection it is
about to trust cannot tell an impostor from the real server.

```sh
makima invite        # another one, for the next machine
makima status        # what this machine can see, and anything wrong
makima down          # stop, and put this machine back
```

Each node is handed an address from `100.64.0.0/10` and learns about the others
automatically. Nodes appearing and disappearing propagate within milliseconds —
the daemon holds a long poll open, so a change is pushed rather than discovered
on a timer.

### Services publish themselves

Anything listening on `127.0.0.1` is put on the mesh as it appears, and taken
off again when it stops. Start Ollama and it is at `desktop.makima:11434` from
your laptop a few seconds later. Start a dev server and it is reachable from
the sofa. There is no command.

That is a deliberate policy: **your mesh is trusted the way this machine is.**
It is the right default for the machines one person owns, and the wrong one the
moment somebody else's laptop joins — so the daemon says which it is doing at
startup, and `makimad -no-auto-serve` turns it off.

```sh
makima allow 8080:3000   # publish a port on purpose, on a different mesh port
makima deny  11434       # keep a port off the mesh, and keep it off
```

`deny` is recorded rather than merely applied, because the scanner runs again
in five seconds and would otherwise put back whatever you just withdrew.

### Getting a shell

```sh
makima ssh desktop
makima possess desktop     # the same command
```

Sugar over `ssh desktop.makima`, which has always worked — `sshd` listens on
every address, so a peer is reachable the moment the tunnel is up. What this
removes is having to remember the suffix.

### die

`makima up` adds a `die` alias to your shell as a shortcut for `makima down`.
It is a fenced block in your own startup file; delete it if you would rather
not have it.

### Administering a mesh

The one machine holding the coordination plane has `makima-server`, and it is
where the mesh is administered from:

```sh
makima-server nodes                  # every machine on it
makima-server forget -name laptop    # evict one; every node drops it at once
makima-server acl set -file p.json   # who may reach whom
makima-server lock status            # stop trusting this server about membership
```

### Reaching a home server that will not cooperate

This is the problem makima was built for, and it is worth being precise about,
because it usually looks like one problem and is three.

A desktop running Ollama or ComfyUI is unreachable from your laptop. You check
the network, and the network is fine. What is actually happening is some
combination of:

1. **The service is bound to localhost.** Ollama, ComfyUI, Open WebUI, Jupyter
   and vLLM all default to `127.0.0.1`. No amount of correct networking reaches
   a socket that is only listening on loopback.
2. **The host firewall is dropping it.** Arch with GNOME often means firewalld;
   Ubuntu often means ufw. Neither says anything when it drops a packet, and
   the symptom is a connection timeout — indistinguishable from a routing fault.
3. **The router will not hairpin.** Once you have given up and set up a public
   hostname and a port forward, it works from outside the house and fails from
   inside it, because most consumer routers will not send a packet back in
   through the WAN address it just came out of.

The usual escalation makes all three worse: rebind to `0.0.0.0`, which exposes
the service to every device on the LAN; open a firewall port, which exposes it
further; forward it on the router, which exposes it to the internet.

makima removes the LAN from the question entirely:

```sh
# on the desktop
makima up
```

```sh
# from anywhere else on the mesh
curl http://desktop.makima:11434/api/tags
```

Nothing in between. The daemon sees Ollama listening on loopback and publishes
it; `makima allow 11434 -name ollama` is only needed if you want to choose the
name or the mesh port.

A service on another machine on that desktop's network — a printer, a NAS, a
switch's web page — takes a three-part form instead, and the machine behind it
never learns the mesh exists:

```sh
sudo makima allow 8080:192.168.1.50:80 -name printer
```

The daemon listens on the desktop's **mesh address** and forwards to
`127.0.0.1:11434`. Nothing about Ollama changes — it stays bound to localhost,
where it was right to be. The listener does not exist on your LAN, so nothing
on your LAN can reach it. No port is forwarded and the router is never
involved, which is why hairpinning stops mattering: the packets never go near
it.

What does reach the service is what got through WireGuard's cryptographic
authentication and then the mesh's access policy. That is the "requests that
arrive in the name of makima just work" property, made literal.

The firewall is handled too. On start the daemon detects firewalld, ufw, or a
bare iptables ruleset and tells it to trust the tunnel interface — one narrow
rule, removed again on exit, opening no port to the LAN or the internet. Pass
`-no-firewall` if you would rather do it yourself, and see `makima firewall
status` either way.

And when something still is not right:

```sh
makima doctor
```

It checks the things that merely *look* like network faults first, in the order
they usually turn out to be the cause, and prints the exact command to fix each
one.

### Working from anywhere

Two machines on the same network find each other without help. Two behind
different NATs need somewhere to meet. Put a relay on anything with a public
address:

```sh
makima-relay serve
makima-server relay add -url <that host>:3478 -key <the relay's key>
```

That is the whole configuration. Every node connects to it, and sessions that
cannot start directly start relayed and upgrade the moment a direct path is
found — so adding a relay is what makes the mesh work from a hotel, a phone
tether, or a corporate network, not just from home.

A relay holds no WireGuard key and decrypts nothing. Running one costs you
nothing in confidentiality, which is why it is reasonable to put one on a cheap
VPS and forget about it.

### The web interface

```sh
sudo makimad -ui 127.0.0.1:8088 -ui-write
makima ui
```

(`makima up` starts the daemon without the UI; pass `-ui` yourself to have one.)

One page: this machine, every peer with the path currently in use and its
latency, everything published from here, and the diagnosis. Services other
nodes publish appear as links you can click — the desktop's Open WebUI is a
link on your laptop, which is the entire point.

Bound to loopback by default. Bind it to the node's mesh address instead to
reach it from another machine, and note the trade: `-ui-write` on a
non-loopback address means anyone who can reach that address controls the node.
Without it the page is read-only, which is usually what you want when you are
just looking at a headless box from your laptop.

### Names

```sh
makima-server dns on
```

Then `ssh laptop.makima` works from any node. Only that suffix is routed to the
mesh resolver; the machine's ordinary DNS is untouched, and it is put back when
the daemon exits.

### Access control

By default every node may reach every other node, which is the right default
for the machines one person owns. When it stops being right:

```json
{
  "groups": { "group:laptops": ["laptop", "phone"] },
  "acls": [
    { "action": "accept", "src": ["group:laptops"], "dst": ["tag:server:22,443"] },
    { "action": "accept", "src": ["*"],             "dst": ["printer:631"] }
  ]
}
```

```sh
makima-server acl set -file policy.json
```

Tags come from the credential a machine joined with — `makima-server authkey
-tags server` — never from anything the machine says about itself, because a
node that could tag itself could grant itself whatever the tag confers.

The policy is enforced twice, in two places, for two reasons. The control plane
applies it when building a netmap, so a node is never even *told* about a peer
it may not reach: a key and an address it never receives are a key and an
address it cannot misuse. The node applies the compiled filter to inbound
packets, because visibility cannot express ports. Enforcement is on ingress —
a compromised sender will not filter itself.

### Reaching things that are not on the mesh

A machine can offer to route a subnet, or to carry general internet traffic:

```sh
sudo makima set -advertise-routes 192.168.1.0/24
sudo makima set -advertise-exit-node true
```

Offering is not enabling. A node can claim any prefix it likes, including one
that would hijack the whole internet, so nothing is installed anywhere until
somebody approves it:

```sh
makima-server routes ls
makima-server routes approve -name nas -all
```

To use an exit node: `sudo makima set -exit-node gateway`.

### Not trusting your own control server

Everything above is arranged so that compromising the control plane buys as
little as possible: it never sees a private key, never carries a packet, and
cannot decrypt anything two nodes say to each other. What it *can* do is lie
about membership — hand you a peer you never authorised.

The network lock closes that:

```sh
makima-server lock init      # generates a signing key, kept off the server
makima-server lock sign
makima-server lock enable
```

Node keys are now signed by an authority whose private half lives with you, not
with the server, and every node verifies its peers itself before admitting them
to the data plane. A server that invents a peer has to forge a signature it
holds no key for, and the invention is rejected by the entire mesh.

This is why the node and machine keys were separated in the very first commit
rather than retrofitted: signing the WireGuard key specifically is what makes
the guarantee mean anything, and it only works if that key was never the same
thing as the node's identity to the server.

### Without a control server

A mesh of two or three machines that never change does not need one. `makima
init` and `makima peer add` maintain the peer list by hand, and the daemon runs
identically:

```sh
makima init -name laptop -addr 100.64.0.1
makima peer add -name desktop -key <public key> -addr 100.64.0.2 \
                -endpoint 192.168.1.50:51820
makima up
```

Only one side needs an `-endpoint`. Whichever machine speaks first teaches the
other where it lives, and the keepalive holds that path open afterwards. A
static mesh gets an ordinary UDP socket rather than the path-selecting one —
there is no control plane to tell it about relays and no disco keys to probe
with, so there would be nothing for it to select between.

### Addressing

Addresses come from `100.64.0.0/10`, RFC 6598 carrier-grade NAT space. It is
routable enough to be useful and reserved enough that it will not collide with
the `10.0.0.0/8` and `192.168.0.0/16` ranges every home and office LAN is
already using.

Only `/32` host routes are ever installed, one per peer. That is mostly an ACL
decision — routing the whole `/10` into the tunnel would blackhole traffic to
mesh addresses this node cannot actually see — but it also means makima
coexists with Tailscale on the same machine: a `/32` wins over Tailscale's
`/10` by longest-prefix match.

## How it fits together

**Data plane.** A userspace WireGuard device on a TUN interface. Userspace
rather than the kernel module even on Linux, for one reason: it lets the engine
be handed a custom socket. Everything below depends on that.

**The socket.** WireGuard wants a peer to have one endpoint — an address to
send to. A mesh that survives NAT cannot offer it one, because the way to reach
a peer changes: a relay at first, a LAN address once both ends notice they are
on the same network, a hole-punched public address after that, and back to the
relay when the laptop moves. Rebuilding the WireGuard configuration on each
change would tear down live sessions for what is only a routing decision.

So the endpoint handed to WireGuard is not an address at all. It is the peer's
node key, and `internal/magicsock` decides — per packet, invisibly — which path
that key currently resolves to. WireGuard sees one stable endpoint for the life
of the peer and never learns that anything moved.

**Control plane.** The thing that answers, for one node: who am I, and who may
I talk to? A node holds a request open against the server, and the server holds
it until the mesh actually changes, which turns polling into push without
either side maintaining a connection protocol of its own. Every minute it
answers anyway, so a poll killed by some intermediary shows up as a missed
heartbeat rather than a silent desync.

**Relay.** A dumb forwarder keyed by public key. It learns which node sits on
which connection and copies frames between them, and that is the entire
service. Because it only ever forwards already-encrypted WireGuard packets it
is fully untrusted.

**Discovery.** Each node gathers candidate addresses for itself three ways,
each blind where the others are not: its own interface addresses (right on a
LAN, useless behind NAT), addresses observed by STUN servers and by peers
(right on the internet, absent until something answers), and a port mapping
requested from the router (right when the router cooperates). Peers then probe
every candidate from both ends at once and keep the lowest-latency path that
answers.

The probes are sealed under a third keypair — the disco key — so path discovery
works before any WireGuard session exists and a captured probe reveals nothing
about the data path.

### Three keys, on purpose

Every node holds three separate Curve25519 keypairs:

- the **node** key, which is the WireGuard key and encrypts traffic;
- the **machine** key, which identifies the device to the control server;
- the **disco** key, which authenticates NAT-traversal probes.

The split is a security property, not bookkeeping. The control server only ever
learns public halves, so it cannot read traffic between nodes. The worst it can
do is lie about *membership* — and that is exactly what the network lock takes
away.

Control messages are sealed with NaCl box under the machine key. There is no
separate authentication step: only the holder of the right private key can
produce a payload that opens, so a successful decryption *is* the proof of
identity. The relay handshake and disco probes work the same way, through one
shared primitive in `internal/key`.

### Preshared keys

A pair of nodes can additionally share a **preshared key**: 32 symmetric bytes
mixed into their WireGuard handshake alongside the Curve25519 exchange. It
authenticates nobody — two machines with a matching preshared key and the wrong
node keys still cannot talk. What it buys is a hedge against Curve25519 itself.
An adversary recording your traffic today and breaking X25519 in twenty years
still faces a secret that never crossed the wire.

```sh
makima genkey -psk                       # prints one line; use it twice
makima peer add -name desktop -key ... -addr 100.64.0.2 -psk <the key>
```

Both sides must set the same one. A preshared key configured on one end only
does not weaken the tunnel, it stops it: the handshake fails and nothing says
why.

The control plane never carries them. It has no use for one, and a server that
could set preshared keys could hand two peers different ones and sever them
silently — so whatever a server sends in that field is discarded on arrival,
before anything reads it. Preshared keys reach a node the only way a symmetric
secret can: out of band, in a static config or a pairing address.

### The admin socket

`makima-server` keeps its state in one JSON file, held in memory by whichever
process opened it. That is fine for one process and actively wrong for two — a
CLI that mints a credential by editing the file is invisible to a running
server, which still holds, and will later overwrite with, its own stale copy.

So every administrative subcommand talks to the running server over a Unix
socket beside the state file. Its permissions are the whole access control
story: reaching it already requires being able to write the state file. When no
server is running there is no conflict, and they fall back to the file
directly.

Unix socket paths are capped near 104 bytes by the OS, and exceeding it fails
with a bare `invalid argument`. If the state file lives somewhere deep, pass
`-socket /tmp/makima.sock`.

## Known limits

- **The machine holding the mesh has to be reachable by the others.** That is
  self-hosting rather than a limitation of makima, but it is the thing most
  likely to surprise: a coordination plane behind a home NAT makes a mesh that
  only works from inside that house.
- **One relay at a time.** Two nodes can only meet on a relay they are both
  connected to, and a relay does not forward to other relays. Registering
  several gives you failover, not load spreading: the control plane picks one
  and the whole mesh follows.
- **No UPnP.** NAT-PMP and PCP are spoken; UPnP IGD would need SSDP discovery
  and SOAP for a shrinking share of routers, and every router that speaks only
  UPnP still works through the relay.
- **Subnet routers and exit nodes are Linux-only.** They need NAT, which on
  macOS means editing the system pf configuration — not something a daemon
  should do behind an operator's back.
- **Mesh DNS on Linux needs systemd-resolved.** Without it there is no
  per-interface resolver, and pointing the system at the mesh resolver would
  capture every lookup on the machine rather than just `*.makima`.
- **IPv4 only inside the tunnel.** The socket is dual-stack and IPv6 endpoints
  work as paths; mesh addresses themselves are v4.
- **Published services are TCP only.** A UDP service — a game server, a DNS
  resolver on a peer — is reachable at the peer's mesh address directly, but
  `makima allow` does not forward it, and it is not published automatically.
- **The firewall is configured automatically on Linux only,** and not at all
  under a bare nftables ruleset: in nftables every table sees every packet, so
  an accept rule makima owns would not override a drop in yours. `makima
  doctor` prints the rule to add instead of pretending.
- **Automatic publishing trusts the whole mesh.** Every loopback service on a
  node is reachable by every node permitted to see it — including a Postgres
  with trust auth, a debug port, or an unauthenticated admin panel. Right for
  the machines one person owns; wrong the moment the mesh has somebody else's
  laptop on it, at which point use ACLs or `-no-auto-serve`.
- **No replay protection on the control channel.** Messages are sealed and
  authenticated, but nonces are not tracked, so a captured registration could
  be replayed to revert a node's key and endpoints to older values.

## Layout

```
cmd/makima          CLI — join a mesh, or maintain a static one
cmd/makimad         node daemon — brings up the tunnel, follows the netmap
cmd/makima-server   the control plane
cmd/makima-relay    the relay

internal/key        Curve25519 keypairs, and the sealed-box primitive
internal/wg         userspace WireGuard on a TUN device
internal/magicsock  path selection: relay, direct, and the upgrade between
internal/relay      the forwarder, its client, and its wire format
internal/disco      the probe protocol that finds direct paths
internal/stun       asking a public server what address we appear to come from
internal/portmap    asking the router to forward a port (NAT-PMP, PCP)
internal/serve      publishing a local port on the mesh, and nowhere else
internal/localapi   the daemon's local API and the embedded web interface
internal/netmap     the mesh's view of itself; renders to a WireGuard config
internal/control    the coordination protocol, its server, client, and store
internal/policy     who may talk to whom, and the filter nodes enforce
internal/dnsserver  mesh name resolution
internal/netcfg     per-platform addresses, routes, resolvers, and NAT
internal/conf       on-disk node identity
```

## License

MIT
