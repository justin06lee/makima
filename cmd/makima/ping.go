package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/justin06lee/makima/internal/conf"
	"github.com/justin06lee/makima/internal/localapi"
)

// `makima ping` answers the question path selection otherwise keeps to itself.
//
// A mesh that works is not the same as a mesh that works *well*. Traffic
// through a relay and traffic straight to the machine next to you look
// identical from the outside — same address, same commands, same everything
// except an order of magnitude of latency and somebody else's bandwidth bill.
// Until now the only way to tell was to read `makima status` and know what
// "relay" in the path column implied.
//
// The important flag is -until-direct. Hole punching is not instant and not
// guaranteed: it depends on what two routers are willing to do, and the honest
// answer for the first few seconds is "not yet". Waiting for it, and then
// saying plainly whether it happened, turns that from a mystery into a result.

// pingInterval is how often the path is re-probed while waiting.
//
// A second, matching what people expect from ping. Probing is one small packet
// per candidate address, so the cost is nothing next to being able to watch a
// path come up in real time.
const pingInterval = time.Second

func pingCmd(args []string) error {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	path := fs.String("config", conf.DefaultPath, "config path")
	untilDirect := fs.Bool("until-direct", false, "keep probing until the path stops going through a relay")
	count := fs.Int("c", 0, "stop after this many probes (0 means keep going)")
	wait := fs.Duration("t", 30*time.Second, "give up after this long")
	if err := fs.Parse(args); err != nil {
		return err
	}

	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("which machine? (try: makima ping desktop — 'makima status' lists them)")
	}
	name := rest[0]

	c, err := dialDaemon(*path)
	if err != nil {
		return err
	}

	// Ctrl-C ends a ping rather than killing it: the summary is the useful
	// part, and a person watching a path fail to come up wants to know how
	// long they waited.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT)
	defer signal.Stop(stop)

	deadline := time.Now().Add(*wait)
	if !*untilDirect && *count == 0 {
		// A plain ping with no bound is one probe and a report, not an endless
		// stream. The stream is what -until-direct and -c are for.
		*count = 1
	}

	started := time.Now()
	sent := 0
	direct := false
	var last localapi.Ping

	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		p, err := c.Ping(name)
		if err != nil {
			return err
		}
		last = p
		sent++
		fmt.Println(pingLine(p))

		if p.Direct {
			direct = true
			if *untilDirect {
				break
			}
		}
		if *count > 0 && sent >= *count {
			break
		}
		if time.Now().After(deadline) {
			break
		}

		select {
		case <-ticker.C:
		case <-stop:
			fmt.Println()
			return pingSummary(last, direct, time.Since(started), *untilDirect)
		}
	}

	return pingSummary(last, direct, time.Since(started), *untilDirect)
}

// pingLine renders one probe.
func pingLine(p localapi.Ping) string {
	switch {
	case p.Direct:
		return fmt.Sprintf("%-15s direct  %s%s", p.Address, p.Path[len("direct "):], rtt(p.Latency))
	case p.RelayURL != "":
		return fmt.Sprintf("%-15s relay   %s%s", p.Address, p.RelayURL, rtt(p.RelayLatency))
	default:
		return fmt.Sprintf("%-15s no path yet%s", p.Address, tryingSuffix(p))
	}
}

// rtt renders a round-trip time, or nothing at all when it has not been
// measured. A blank is more honest than "0ms".
func rtt(d time.Duration) string {
	if d == 0 {
		return ""
	}
	return fmt.Sprintf("  %s", d.Round(100*time.Microsecond))
}

// tryingSuffix names what is being attempted, because "which addresses did it
// even try" is the next question after "it is not connecting".
func tryingSuffix(p localapi.Ping) string {
	if len(p.Candidates) == 0 {
		return "  (no address to try, and no relay)"
	}
	return fmt.Sprintf("  (trying %s)", p.Candidates[0])
}

// pingSummary is the verdict, and the reason -until-direct exists.
func pingSummary(p localapi.Ping, direct bool, elapsed time.Duration, untilDirect bool) error {
	fmt.Println()

	switch {
	case direct:
		msg := fmt.Sprintf("Direct path to %s.", p.Name)
		if untilDirect {
			msg = fmt.Sprintf("Direct path to %s after %s.", p.Name, elapsed.Round(100*time.Millisecond))
		}
		fmt.Println(msg)
		if p.RelayLatency > 0 && p.Latency > 0 && p.RelayLatency > p.Latency {
			fmt.Printf("Traffic is going straight there — %s instead of %s through the relay.\n",
				p.Latency.Round(100*time.Microsecond), p.RelayLatency.Round(100*time.Microsecond))
		}
		return nil

	case p.RelayURL != "" && untilDirect:
		fmt.Printf("Still going through %s after %s.\n", p.RelayURL, elapsed.Round(100*time.Millisecond))
		fmt.Println()
		fmt.Println("It works, but every packet takes a detour. The usual cause is that")
		fmt.Println("neither router will open a path, which is what 'makima doctor' checks.")
		fmt.Println("Forwarding UDP to one of the two machines fixes it for both.")
		return nil

	case p.RelayURL != "":
		fmt.Printf("Reachable through %s. Relayed, not direct — 'makima ping -until-direct %s' waits for an upgrade.\n", p.RelayURL, p.Name)
		return nil

	default:
		return fmt.Errorf("no path to %s: nothing has answered, and there is no relay to fall back to", p.Name)
	}
}
