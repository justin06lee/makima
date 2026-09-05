package main

import (
	"testing"

	"github.com/justin06lee/makima/internal/control"
)

func TestControlURL(t *testing.T) {
	for _, tc := range []struct {
		name  string
		given string
		want  string
	}{
		{"a bare address gets the default port", "192.168.1.50", "http://192.168.1.50:8080"},
		{"a hostname does too", "vps.example.com", "http://vps.example.com:8080"},
		{"an explicit port is kept", "vps.example.com:9000", "http://vps.example.com:9000"},
		// The case for somebody already self-hosting: a reverse proxy or a
		// Cloudflare tunnel is already carrying traffic into the house, and
		// the coordination plane can ride the same path.
		{"a full URL is used verbatim", "https://makima.example.dev", "https://makima.example.dev"},
		{"http URLs too", "http://makima.example.dev", "http://makima.example.dev"},
		{"a trailing slash is dropped", "https://makima.example.dev/", "https://makima.example.dev"},
		{"a URL with a port survives", "https://makima.example.dev:8443", "https://makima.example.dev:8443"},
		{"surrounding space is ignored", "  10.0.0.5  ", "http://10.0.0.5:8080"},
		// An IPv6 literal is full of colons and none of them is a port.
		{"an IPv6 literal is not mistaken for host:port", "2001:db8::1", "http://[2001:db8::1]:8080"},
		{"a bracketed IPv6 with a port is kept", "[2001:db8::1]:9000", "http://[2001:db8::1]:9000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := controlURL(tc.given); got != tc.want {
				t.Errorf("controlURL(%q) = %q, want %q", tc.given, got, tc.want)
			}
		})
	}
}

// The supervisor decides the server is up by dialling its admin socket, and
// `makima up` then talks to it over the same socket. Both have to be the path
// the server itself listens on — which the server names — or `up` waits twenty
// seconds on a socket nobody opens and tears down a server that was working.
func TestServerSocketIsTheServersOwn(t *testing.T) {
	want := control.SocketPath(serverStatePath)
	if got := controlDaemon().Socket; got != want {
		t.Fatalf("supervisor waits on %s, but the server listens on %s", got, want)
	}
	if got := serverSocket(); got != want {
		t.Fatalf("serverSocket() = %s, want %s", got, want)
	}
}

// The desktop app cannot see inside /var/lib/makima, so it decides whether
// this device holds the network by looking for the service `up` registered —
// by these names, spelled out again in desktop/src-tauri/src/daemon.rs.
// Renaming either means changing both.
func TestServerServiceNamesAreWhatTheAppLooksFor(t *testing.T) {
	svc := controlDaemon().Service
	if svc.Label != "sh.makima.server" {
		t.Errorf("launchd label = %q; the app looks for sh.makima.server.plist", svc.Label)
	}
	if svc.Unit != "makima-server" {
		t.Errorf("systemd unit = %q; the app looks for makima-server.service", svc.Unit)
	}
}
