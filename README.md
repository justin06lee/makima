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

**Feature-complete.** A node joins with a credential, is handed an address, and
receives the mesh's membership over a long poll that pushes changes as they
happen. It reaches its peers directly where it can and through a relay where it
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

Pick a machine to hold the control plane — anything the others can reach. Run:

```sh
makima-server serve
```

It prints its public key on startup and stores everything in
`/var/lib/makima/control.json`. Mint a credential for each machine you want to
add:

```sh
makima-server authkey -reusable -expiry 1h
```

That prints a ready-to-paste join command. On each machine:

```sh
sudo makima join -server http://<control-host>:8080 \
                 -authkey makima_... \
                 -serverkey <the server's public key>
```

Then bring the tunnel up:

```sh
sudo makimad
```

Each node is handed an address from `100.64.0.0/10` and learns about the others
automatically. Nodes appearing and disappearing propagate within milliseconds —
the daemon holds a long poll open, so a change is pushed rather than discovered
on a timer.

`makima status` shows what a node can see and how it is reaching it.
`makima-server nodes` lists the mesh. `makima-server forget -name N` evicts a
machine and every other node drops it on the spot.

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
sudo makimad
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
internal/netmap     the mesh's view of itself; renders to a WireGuard config
internal/control    the coordination protocol, its server, client, and store
internal/policy     who may talk to whom, and the filter nodes enforce
internal/dnsserver  mesh name resolution
internal/netcfg     per-platform addresses, routes, resolvers, and NAT
internal/conf       on-disk node identity
```

## License

MIT
