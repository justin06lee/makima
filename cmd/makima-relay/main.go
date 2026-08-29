// Command makima-relay forwards packets between nodes that cannot reach each
// other directly.
//
// It is the least trusted thing in makima and the easiest to run. It holds no
// WireGuard key, decrypts nothing, and keeps no state beyond its own identity
// — a relay's entire memory of the mesh is the set of connections currently
// open to it. That is what makes it reasonable to put one on a cheap VPS with
// a public address and never think about it again.
//
// One relay serves a whole mesh. Nodes can only meet on a relay they are both
// connected to, so running several is failover, not load spreading: the
// control plane picks one and the whole mesh follows.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/justin06lee/makima/internal/relay"
)

var version = "dev"

func main() {
	log.SetFlags(0)
	log.SetPrefix("makima-relay: ")

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "key":
		err = showKey(os.Args[2:])
	case "version":
		fmt.Println(version)
		return
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "makima-relay: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `makima-relay — the fallback path for a makima mesh

  makima-relay serve [-addr :`+strconv.Itoa(relay.DefaultPort)+`] [-status 127.0.0.1:3479]
  makima-relay key

every command takes -state PATH (default `+relay.DefaultStatePath+`)

register it with the control plane:
  makima-server relay add -url <host>:`+strconv.Itoa(relay.DefaultPort)+` -key <the key above>
`)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	statePath := fs.String("state", relay.DefaultStatePath, "path to the relay's identity")
	addr := fs.String("addr", ":"+strconv.Itoa(relay.DefaultPort), "address to listen on")
	status := fs.String("status", "", "optional address for a plaintext status endpoint, e.g. 127.0.0.1:3479")
	if err := fs.Parse(args); err != nil {
		return err
	}

	id, err := relay.LoadIdentity(*statePath)
	if err != nil {
		return err
	}

	srv := relay.NewServer(id.PrivateKey, log.Default())

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *addr, err)
	}
	defer ln.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var statusSrv *http.Server
	if *status != "" {
		statusSrv = &http.Server{
			Addr:              *status,
			Handler:           statusHandler(srv),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			if err := statusSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("status endpoint: %v", err)
			}
		}()
	}

	go func() {
		<-ctx.Done()
		ln.Close()
		srv.Close()
		if statusSrv != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = statusSrv.Shutdown(shutdownCtx)
		}
	}()

	log.Printf("listening on %s", *addr)
	log.Printf("state    %s", *statePath)
	log.Printf("key      %s", srv.PublicKey())
	if *status != "" {
		log.Printf("status   http://%s/", *status)
	}
	log.Print("register it with: makima-server relay add -url <host>:" + strconv.Itoa(relay.DefaultPort) + " -key " + srv.PublicKey().String())

	if err := srv.Serve(ln); err != nil {
		return err
	}
	log.Print("stopped")
	return nil
}

func showKey(args []string) error {
	fs := flag.NewFlagSet("key", flag.ExitOnError)
	statePath := fs.String("state", relay.DefaultStatePath, "path to the relay's identity")
	if err := fs.Parse(args); err != nil {
		return err
	}

	id, err := relay.LoadIdentity(*statePath)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", id.PrivateKey.Public())
	return nil
}

// statusHandler exposes counters for monitoring.
//
// Bound to a separate, explicitly-configured address rather than served on the
// relay port: connected node keys are the one thing a relay knows that is
// worth keeping to itself, since the list is a map of who is on the mesh.
func statusHandler(srv *relay.Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		st := srv.Stats()
		fmt.Fprintf(w, "connected  %d\n", srv.ConnectedCount())
		fmt.Fprintf(w, "accepted   %d\n", st.Accepted.Load())
		fmt.Fprintf(w, "rejected   %d\n", st.Rejected.Load())
		fmt.Fprintf(w, "forwarded  %d\n", st.Forwarded.Load())
		fmt.Fprintf(w, "dropped    %d\n", st.Dropped.Load())
	})
	return mux
}
