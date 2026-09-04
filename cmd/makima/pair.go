package main

import (
	ctxpkg "context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/key"
	"github.com/justin06lee/makima/internal/localapi"
	"github.com/justin06lee/makima/internal/netmap"
	"github.com/justin06lee/makima/internal/pair"
)

// `makima pair` is makima without a server.
//
// The rest of the CLI assumes a mesh you keep: something coordinates it, and
// machines join by invitation. That is the right shape for the network you
// actually run. It is the wrong shape for two machines that want to talk once,
// and it is a poor first impression — the shortest path to seeing whether any
// of this works should not begin with standing up a coordination plane.
//
// Pairing is the alternative all the way down. One side runs `makima pair` and
// gets a string; the other runs `makima pair <string>`. Each writes the other
// into its own configuration and that is the entire mesh. Nothing is
// administered, because there is nothing to administer.

// pairWait bounds how long a knock keeps trying.
//
// Generous, because the slow case is real: two machines behind different NATs
// meeting at a relay, where the first few knocks are spent waiting for both
// relay sessions to come up.
const pairWait = 45 * time.Second

func pairCmd(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	name := fs.String("name", "", "this machine's name (defaults to the hostname)")
	relay := fs.String("relay", "", "a relay to meet at, HOST:PORT — needed when neither machine is directly reachable")
	relayKey := fs.String("relay-key", "", "the relay's public key, if it is not this machine's own")
	psk := fs.String("psk", "", "a preshared key to bind the pairing to (makima genkey -psk)")
	window := fs.Duration("for", pair.DefaultWindow, "how long to accept pairings")
	stop := fs.Bool("stop", false, "close an open pairing window")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// A pasted address is the whole argument, checked before anything asks for
	// a password: being prompted for root and then told the string was
	// mistyped is a bad trade.
	var target string
	if rest := fs.Args(); len(rest) > 0 {
		if _, err := pair.Decode(rest[0]); err != nil {
			return err
		}
		target = rest[0]
	}

	if err := mustBeRoot(); err != nil {
		return err
	}

	if err := ensureServerless(*path, *name, *relay, *relayKey); err != nil {
		return err
	}

	c, err := dialDaemon(*path)
	if err != nil {
		return err
	}

	if *stop {
		if err := c.ClosePairing(); err != nil {
			return err
		}
		fmt.Println("Pairing closed. This machine no longer answers knocks.")
		return nil
	}

	if target != "" {
		return pairWith(c, target, *psk)
	}
	return pairListen(c, *window, *psk)
}

// pairListen publishes this machine's address and waits to be knocked on.
func pairListen(c *localapi.Client, window time.Duration, psk string) error {
	st, err := c.OpenPairing(int(window.Seconds()))
	if err != nil {
		return err
	}

	address := st.Address
	if psk != "" {
		// The preshared key is folded into the address here rather than in the
		// daemon, because the daemon must not hold one: the whole point is
		// that a secret typed on this machine and pasted onto the other never
		// sits at rest anywhere in between.
		address, err = withPSK(address, psk)
		if err != nil {
			return err
		}
	}

	fmt.Println("Run this on the other machine:")
	fmt.Println()
	fmt.Printf("  makima pair %s\n", address)
	fmt.Println()
	fmt.Printf("Listening until %s. 'makima pair -stop' closes it early.\n", st.Expires.Format(time.Kitchen))
	if psk != "" {
		fmt.Println("This address carries a preshared key, so it is the whole secret — send it somewhere private.")
	}
	return nil
}

// pairWith knocks on somebody else's address.
func pairWith(c *localapi.Client, address, psk string) error {
	if psk != "" {
		var err error
		if address, err = withPSK(address, psk); err != nil {
			return err
		}
	}

	fmt.Println("Knocking…")
	res, err := c.Pair(address, pairWait)
	if err != nil {
		return err
	}

	fmt.Printf("Paired with %s at %s.\n", res.Name, res.Address)
	fmt.Println()
	fmt.Printf("  makima ssh %s\n", res.Name)
	fmt.Println("  makima status        what you can see now")
	return nil
}

// withPSK folds a preshared key into an address.
//
// Both ends have to end up with the same one, which is why it is a flag on
// both sides rather than something baked in by whichever machine spoke first.
func withPSK(address, psk string) (string, error) {
	shared, err := key.ParseShared(psk)
	if err != nil {
		return "", fmt.Errorf("parse preshared key: %w", err)
	}

	a, err := pair.Decode(address)
	if err != nil {
		return "", err
	}
	a.PSK = shared
	return pair.Encode(a)
}

// ensureServerless makes sure there is a serverless configuration and a daemon
// running on it.
//
// The first `makima pair` on a machine is also its `makima up`: a mesh with no
// control plane has no bootstrap step, so there is nothing for a separate
// command to do that this one cannot.
func ensureServerless(path, name, relayURL, relayKey string) error {
	f, err := conf.Load(path)
	switch {
	case err == nil:
		if f.Managed() {
			return errors.New("this machine belongs to a mesh with a coordination plane; add machines with 'makima invite' instead of pairing")
		}
		if !f.Serverless {
			// A hand-maintained static mesh predates pairing and gets an
			// ordinary UDP socket. Turning pairing on changes which socket the
			// daemon uses, so it is an explicit step rather than a surprise.
			return errors.New("this machine is a hand-maintained static mesh; 'makima peer add' is how it gains peers")
		}
		if relayURL != "" {
			if err := setRelay(path, f, relayURL, relayKey); err != nil {
				return err
			}
		}

	case os.IsNotExist(errors.Unwrap(err)) || errors.Is(err, os.ErrNotExist):
		if err := initServerless(path, name, relayURL, relayKey); err != nil {
			return err
		}

	default:
		return err
	}

	d := daemonFor(path)
	ctx, cancel := ctxpkg.WithTimeout(ctxpkg.Background(), time.Minute)
	defer cancel()
	return d.Start(ctx, startWait)
}

// initServerless writes a fresh serverless configuration.
//
// The mesh address is derived from the node key rather than chosen, because
// there is nobody to choose. Both ends compute the same answer from public
// information, which is what removes address negotiation from a serverless
// mesh entirely.
func initServerless(path, name, relayURL, relayKey string) error {
	if name == "" {
		h, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("no -name given and the hostname is unreadable: %w", err)
		}
		name = h
	}

	nodeKey, machineKey, discoKey, err := conf.NewIdentity()
	if err != nil {
		return err
	}

	addr := pair.MeshAddr(nodeKey.Public())
	f := &conf.File{
		NodeKey:    nodeKey,
		MachineKey: machineKey,
		DiscoKey:   discoKey,
		Serverless: true,
		Self: netmap.Node{
			ID:        1,
			Name:      name,
			Key:       nodeKey.Public(),
			DiscoKey:  discoKey.Public(),
			Addresses: []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())},
		},
	}
	if relayURL != "" {
		if err := applyRelay(f, relayURL, relayKey); err != nil {
			return err
		}
	}

	if err := conf.Save(path, f); err != nil {
		return err
	}
	fmt.Printf("This machine is %s at %s. No coordination plane — it pairs directly.\n", name, addr)
	return nil
}

// setRelay records a relay on an existing configuration.
func setRelay(path string, f *conf.File, relayURL, relayKey string) error {
	if err := applyRelay(f, relayURL, relayKey); err != nil {
		return err
	}
	return conf.Save(path, f)
}

func applyRelay(f *conf.File, relayURL, relayKey string) error {
	r := netmap.Relay{URL: relayURL}
	if relayKey != "" {
		k, err := key.ParsePublic(relayKey)
		if err != nil {
			return fmt.Errorf("parse relay key: %w", err)
		}
		r.Key = k
	}
	f.HomeRelay = r
	return nil
}
