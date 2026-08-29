// Command makima-server is the coordination plane.
//
// It holds the mesh's membership, hands out addresses, and answers each node's
// long poll with that node's view of the network. It never sees a private key
// and never carries a packet: compromising it lets an attacker lie about who
// belongs, and nothing more.
//
// Administrative subcommands talk to a running server over a Unix socket
// rather than editing its state file, because two processes with independent
// in-memory copies of one JSON file will silently overwrite each other. When
// no server is running there is no such conflict, so they fall back to
// operating on the file directly.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/justin06lee/makima/internal/control"
	"github.com/justin06lee/makima/internal/key"
)

// DefaultStatePath is where the mesh's membership lives.
const DefaultStatePath = "/var/lib/makima/control.json"

// version is stamped by the Makefile from `git describe`.
var version = "dev"

func main() {
	log.SetFlags(0)
	log.SetPrefix("makima-server: ")

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "authkey":
		err = authkey(os.Args[2:])
	case "nodes":
		err = nodes(os.Args[2:])
	case "forget":
		err = forget(os.Args[2:])
	case "key":
		err = showKey(os.Args[2:])
	case "relay":
		err = relayCmd(os.Args[2:])
	case "routes":
		err = routesCmd(os.Args[2:])
	case "acl":
		err = aclCmd(os.Args[2:])
	case "dns":
		err = dnsCmd(os.Args[2:])
	case "lock":
		err = lockCmd(os.Args[2:])
	case "tags":
		err = tagsCmd(os.Args[2:])
	case "expire":
		err = expireCmd(os.Args[2:])
	case "version":
		fmt.Println(version)
		return
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "makima-server: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `makima-server — the coordination plane for a makima mesh

running it:
  makima-server serve   [-addr :8080]
  makima-server key

admitting machines:
  makima-server authkey [-reusable] [-expiry 24h] [-tags tag1,tag2]
  makima-server nodes
  makima-server forget  -name N     remove a machine entirely
  makima-server expire  -name N     make it re-authenticate, keeping its address
  makima-server tags    -name N -tags t1,t2

reaching machines that cannot reach each other:
  makima-server relay add    -url HOST:3478 -key K
  makima-server relay ls
  makima-server relay prefer -url HOST:3478
  makima-server relay rm     -url HOST:3478

names, access, and routing:
  makima-server dns    on [-domain makima] | off | status
  makima-server acl    show | set -file P | reset
  makima-server routes ls | approve -name N [-all] | revoke -name N

not trusting this server about membership:
  makima-server lock init      generate a signing key and trust it
  makima-server lock sign      sign every unsigned node
  makima-server lock enable    start enforcing
  makima-server lock status

every command takes -state PATH (default `+DefaultStatePath+`)
`)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	statePath := fs.String("state", DefaultStatePath, "path to control plane state")
	socketPath := fs.String("socket", "", "admin socket path (default: beside the state file)")
	addr := fs.String("addr", ":8080", "address to listen on")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := control.OpenStore(*statePath)
	if err != nil {
		return err
	}
	handlers := control.NewServer(store, log.Default())

	// Claim the admin socket before binding the public port, so a second
	// server refuses to start rather than racing the first over the state
	// file.
	adminLn, err := control.ListenAdmin(sock(*socketPath, *statePath))
	if err != nil {
		return err
	}
	defer adminLn.Close()

	adminSrv := &http.Server{Handler: handlers.AdminHandler()}
	go func() {
		if err := adminSrv.Serve(adminLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("admin socket: %v", err)
		}
	}()

	srv := &http.Server{
		Addr:    *addr,
		Handler: handlers.Handler(),
		// No WriteTimeout: a map request is *meant* to hang for up to a
		// minute, and a write deadline would cut the long poll off at the
		// knees. ReadHeaderTimeout still protects against a slowloris.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		_ = adminSrv.Shutdown(shutdownCtx)
	}()

	log.Printf("listening on %s", *addr)
	log.Printf("state    %s", *statePath)
	log.Printf("admin    %s", sock(*socketPath, *statePath))
	log.Printf("key      %s", store.ServerKey().Public())
	log.Printf("%d node(s) registered", len(store.Nodes()))
	log.Print("mint a join credential with: makima-server authkey")

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Print("stopped")
	return nil
}

func authkey(args []string) error {
	fs := flag.NewFlagSet("authkey", flag.ExitOnError)
	statePath := fs.String("state", DefaultStatePath, "path to control plane state")
	socketPath := fs.String("socket", "", "admin socket path (default: beside the state file)")
	reusable := fs.Bool("reusable", false, "allow the key to admit more than one node")
	expiry := fs.Duration("expiry", 24*time.Hour, "how long the key stays valid; 0 means forever")
	tags := fs.String("tags", "", "comma-separated policy tags applied to whoever joins with this key")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var tagList []string
	for _, s := range strings.Split(*tags, ",") {
		if s = strings.TrimSpace(s); s != "" {
			tagList = append(tagList, s)
		}
	}

	var (
		a      *control.AuthKey
		srvKey key.Public
		err    error
	)
	if admin, live := control.DialAdmin(sock(*socketPath, *statePath)); live {
		if a, err = admin.MintAuthKeyTagged(*reusable, *expiry, tagList); err != nil {
			return err
		}
		if srvKey, err = admin.ServerKey(); err != nil {
			return err
		}
	} else {
		store, err := control.OpenStore(*statePath)
		if err != nil {
			return err
		}
		if a, err = store.MintAuthKeyTagged(*reusable, *expiry, tagList); err != nil {
			return err
		}
		srvKey = store.ServerKey().Public()
	}

	fmt.Printf("%s\n\n", a.Secret)
	if a.Expires.IsZero() {
		fmt.Print("never expires")
	} else {
		fmt.Printf("expires %s", a.Expires.Local().Format(time.RFC1123))
	}
	if a.Reusable {
		fmt.Print(", reusable\n")
	} else {
		fmt.Print(", single use\n")
	}
	fmt.Printf("\njoin a machine with:\n  sudo makima join -server http://<this-host>:8080 -authkey %s \\\n       -serverkey %s\n",
		a.Secret, srvKey)
	return nil
}

func nodes(args []string) error {
	fs := flag.NewFlagSet("nodes", flag.ExitOnError)
	statePath := fs.String("state", DefaultStatePath, "path to control plane state")
	socketPath := fs.String("socket", "", "admin socket path (default: beside the state file)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var (
		all []control.Node
		err error
	)
	if admin, live := control.DialAdmin(sock(*socketPath, *statePath)); live {
		if all, err = admin.Nodes(); err != nil {
			return err
		}
	} else {
		store, err := control.OpenStore(*statePath)
		if err != nil {
			return err
		}
		all = store.Nodes()
	}

	if len(all) == 0 {
		fmt.Print("no nodes registered\n")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprint(w, "ID\tNAME\tADDRESS\tENDPOINTS\tLAST SEEN\n")
	for _, n := range all {
		eps := "—"
		if len(n.Endpoints) > 0 {
			eps = n.Endpoints[0].String()
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
			n.ID, n.Name, n.Address.Addr(), eps, humanAge(n.LastSeen))
	}
	return w.Flush()
}

func forget(args []string) error {
	fs := flag.NewFlagSet("forget", flag.ExitOnError)
	statePath := fs.String("state", DefaultStatePath, "path to control plane state")
	socketPath := fs.String("socket", "", "admin socket path (default: beside the state file)")
	name := fs.String("name", "", "node to remove")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("forget needs -name")
	}

	if admin, live := control.DialAdmin(sock(*socketPath, *statePath)); live {
		if err := admin.Forget(*name); err != nil {
			return err
		}
	} else {
		store, err := control.OpenStore(*statePath)
		if err != nil {
			return err
		}
		if err := store.Forget(*name); err != nil {
			return err
		}
	}

	fmt.Printf("removed %s; every other node will drop it on its next netmap\n", *name)
	return nil
}

func showKey(args []string) error {
	fs := flag.NewFlagSet("key", flag.ExitOnError)
	statePath := fs.String("state", DefaultStatePath, "path to control plane state")
	socketPath := fs.String("socket", "", "admin socket path (default: beside the state file)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if admin, live := control.DialAdmin(sock(*socketPath, *statePath)); live {
		k, err := admin.ServerKey()
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", k)
		return nil
	}

	store, err := control.OpenStore(*statePath)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", store.ServerKey().Public())
	return nil
}

func humanAge(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t).Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// sock resolves the admin socket path: an explicit -socket wins, otherwise it
// sits beside the state file.
func sock(explicit, statePath string) string {
	if explicit != "" {
		return explicit
	}
	return control.SocketPath(statePath)
}
