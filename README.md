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

**M0 — the data plane works.** The tunnel comes up, peers are configured by
hand, and traffic flows between machines that can already reach each other.
There is no control server and no NAT traversal yet, so a peer needs a
reachable address you type in yourself.

The roadmap below is the order things land in, and it is deliberate. The relay
comes *before* NAT traversal: since sessions legitimately start relayed and
upgrade to direct, a relay-only mesh is not a prototype — it is a correct
network that happens to be slower. That makes M2 the point where this stops
being a project and starts being something you use daily, and everything after
it a performance improvement.

| | | |
|---|---|---|
| **M0** | TUN + WireGuard, static peers | **done** |
| M1 | control server, registration, netmap long-poll | next |
| M2 | relay — works from anywhere, no port forwarding | |
| M3 | disco — STUN, endpoint exchange, hole punching, direct paths | |
| M4 | hard-NAT port prediction, UPnP / NAT-PMP / PCP | |
| M5 | DNS names, ACLs, exit nodes, subnet routes | |
| M6 | SSO, key rotation, node-key signing | |

## Install

```sh
make
```

Builds both binaries and installs them to `/usr/local/bin`. `make update` stops
a running daemon, replaces the binaries, and leaves you ready to start again.

Requires Go 1.25 or newer. Linux and macOS today; Windows cross-compiles but
its address assignment is not wired up yet.

## Use

On the first machine:

```sh
makima init -name laptop -addr 100.64.0.1
```

That writes `/etc/makima/node.json`, generates the node's keypair, and prints
its public key. Do the same on the second machine with a different address,
then introduce them to each other:

```sh
# on laptop
makima peer add -name desktop -key <desktop's public key> -addr 100.64.0.2 \
                -endpoint 192.168.1.50:51820

# on desktop
makima peer add -name laptop -key <laptop's public key> -addr 100.64.0.1
```

Only one side needs an `-endpoint`. Whichever machine speaks first teaches the
other where it lives, and the keepalive holds that path open afterwards.

Bring the tunnel up on both:

```sh
sudo makimad
```

Then `ping 100.64.0.2`. `makima show` prints the current configuration at any
time.

Addresses come from `100.64.0.0/10`, RFC 6598 carrier-grade NAT space. It is
routable enough to be useful and reserved enough that it will not collide with
the `10.0.0.0/8` and `192.168.0.0/16` ranges every home and office LAN is
already using.

## How it fits together

Four subsystems, useless alone and a network together.

**Data plane.** A userspace WireGuard device on a TUN interface. Userspace
rather than the kernel module even on Linux, for one reason that matters later:
it lets the engine be handed a custom socket, so packets can be steered over a
relay or a hole-punched path without WireGuard knowing the difference. That
hook is what makes relay-then-upgrade possible at all.

**Control plane.** The thing that answers, for one node: who am I, and who may
I talk to? Its answer is a netmap — peer keys, addresses, candidate paths, and
a compiled packet filter. In M0 you write that file by hand; from M1 a server
produces it and the daemon long-polls for changes. The struct is the same
either way, which is why growing a control plane never touches the data path.

**Relay.** A dumb forwarder keyed by public key. It is a fallback when a direct
path cannot be established, a rendezvous point for peers that have never met,
and the channel path negotiation itself runs over. Because it only ever
forwards already-encrypted WireGuard packets, it is fully untrusted — running
one costs you nothing in confidentiality.

**Discovery.** Each node gathers candidate addresses for itself: LAN
interfaces, a public address observed via STUN, anything it can open with a
port-mapping protocol. Those get published, redistributed, and probed from both
ends at once. The lowest-latency path that answers wins, and probing never
stops, so the path migrates when you walk from wifi to a phone hotspot.

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

## Layout

```
cmd/makima         CLI — keys, config, peers
cmd/makimad        node daemon — brings up and holds the tunnel
internal/key       Curve25519 keypairs, clamped and redacted
internal/wg        userspace WireGuard on a TUN device
internal/netmap    the mesh's view of itself; renders to a WireGuard config
internal/netcfg    per-platform address and route assignment
internal/conf      on-disk node identity
```

## License

MIT
