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

**M1 — the control plane works.** A node joins with a credential, is handed an
address, and receives the mesh's membership over a long poll that pushes
changes as they happen. Machines on the same network find each other and
connect directly.

There is no relay and no NAT traversal yet, so two machines that cannot already
reach each other over the network will see each other in the netmap and fail to
connect. That is M2 and M3.

The roadmap below is the order things land in, and it is deliberate. The relay
comes *before* NAT traversal: since sessions legitimately start relayed and
upgrade to direct, a relay-only mesh is not a prototype — it is a correct
network that happens to be slower. That makes M2 the point where this stops
being a project and starts being something you use daily, and everything after
it a performance improvement.

| | | |
|---|---|---|
| **M0** | TUN + WireGuard, static peers | **done** |
| **M1** | control server, registration, netmap long-poll | **done** |
| M2 | relay — works from anywhere, no port forwarding | next |
| M3 | disco — STUN, endpoint exchange, hole punching, direct paths | |
| M4 | hard-NAT port prediction, UPnP / NAT-PMP / PCP | |
| M5 | DNS names, ACLs, exit nodes, subnet routes | |
| M6 | SSO, key rotation, node-key signing | |

## Install

```sh
make
```

Builds all three binaries and installs them to `/usr/local/bin`. `make update`
stops a running daemon, replaces the binaries, and leaves you ready to start
again.

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

Each node is handed an address from `100.64.0.0/10` and learns about the
others automatically. Nodes appearing and disappearing propagate within
milliseconds — the daemon holds a long poll open, so a change is pushed rather
than discovered on a timer.

`makima-server nodes` lists the mesh. `makima-server forget -name N` evicts a
machine, and every other node drops it on the spot.

Pinning `-serverkey` is optional; without it the node fetches the key over the
network on first contact and trusts what it gets. That is fine on a network you
control and a genuine exposure on one you do not, since whoever answers becomes
the control plane.

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
other where it lives, and the keepalive holds that path open afterwards.

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

Four subsystems, useless alone and a network together.

**Data plane.** A userspace WireGuard device on a TUN interface. Userspace
rather than the kernel module even on Linux, for one reason that matters later:
it lets the engine be handed a custom socket, so packets can be steered over a
relay or a hole-punched path without WireGuard knowing the difference. That
hook is what makes relay-then-upgrade possible at all.

**Control plane.** The thing that answers, for one node: who am I, and who may
I talk to? Its answer is a netmap — peer keys, addresses, and candidate paths.
A node holds a request open against the server, and the server holds it until
the mesh actually changes, which turns polling into push without either side
maintaining a connection protocol of its own. Every minute it answers anyway,
so a poll killed by some intermediary shows up as a missed heartbeat rather
than a silent desync.

**Relay.** *(M2)* A dumb forwarder keyed by public key: a fallback when a
direct path cannot be established, a rendezvous point for peers that have never
met, and the channel path negotiation itself runs over. Because it only ever
forwards already-encrypted WireGuard packets, it is fully untrusted — running
one costs you nothing in confidentiality.

**Discovery.** *(M3)* Each node gathers candidate addresses for itself and
probes every pair from both ends at once, keeping the lowest-latency path that
answers. Today's version is the shallow one: a node reports the addresses it
can see on its own interfaces, which is enough for two machines on one network
and blind to anything behind NAT.

### Three keys, on purpose

Every node holds three separate Curve25519 keypairs:

- the **node** key, which is the WireGuard key and encrypts traffic;
- the **machine** key, which identifies the device to the control server;
- the **disco** key, which authenticates NAT-traversal probes, so path
  discovery works before any WireGuard session exists.

The split is a security property, not bookkeeping. The control server only ever
learns public halves, so it cannot read traffic between nodes. The worst it can
do is lie about *membership* — hand you a peer you never authorised. That is
the specific attack node-key signing closes in M6, and it is the reason the
keys are separated from the start rather than retrofitted.

Control messages are sealed with NaCl box under the machine key, which is what
Tailscale itself used before its Noise rework. There is no separate
authentication step: only the holder of the right private key can produce a
payload that opens, so a successful decryption *is* the proof of identity.

### The admin socket

`makima-server` keeps its state in one JSON file, held in memory by whichever
process opened it. That is fine for one process and actively wrong for two — a
CLI that mints a credential by editing the file is invisible to a running
server, which still holds, and will later overwrite with, its own stale copy.

So `authkey`, `nodes`, and `forget` talk to the running server over a Unix
socket beside the state file. Its permissions are the whole access control
story: reaching it already requires being able to write the state file. When no
server is running there is no conflict, and they fall back to the file
directly.

Unix socket paths are capped near 104 bytes by the OS, and exceeding it fails
with a bare `invalid argument`. If the state file lives somewhere deep, pass
`-socket /tmp/makima.sock`.

## Layout

```
cmd/makima          CLI — join a mesh, or maintain a static one
cmd/makimad         node daemon — brings up the tunnel, follows the netmap
cmd/makima-server   the control plane

internal/key        Curve25519 keypairs, clamped and redacted
internal/wg         userspace WireGuard on a TUN device
internal/netmap     the mesh's view of itself; renders to a WireGuard config
internal/control    the coordination protocol, its server, client, and store
internal/netcfg     per-platform addresses, routes, and local endpoints
internal/conf       on-disk node identity
```

## License

MIT
