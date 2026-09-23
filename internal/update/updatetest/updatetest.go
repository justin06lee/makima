// Package updatetest serves fake makima releases the way GitHub does, for
// tests of anything that updates.
package updatetest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/justin06lee/subaru"
)

// Release is one fake release: its tag, and the files in this platform's
// archive by name.
type Release struct {
	Tag   string
	Files map[string]string
}

// Script is a stand-in program that prints version when asked, which is all
// an update's dry run needs from a daemon.
func Script(version string) string {
	return fmt.Sprintf("#!/bin/sh\necho %s\n", version)
}

// Suite is every named program as a Script of version.
func Suite(version string, names ...string) map[string]string {
	out := make(map[string]string, len(names))
	for _, n := range names {
		out[n] = Script(version)
	}
	return out
}

// Serve publishes releases over TLS — subaru downloads from nothing else —
// under the API path of justin06lee/makima, the last one as latest, and
// returns the options that point an updater at it.
func Serve(t testing.TB, releases ...Release) []subaru.Option {
	t.Helper()
	type asset struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	}
	blobs := map[string][]byte{}
	byTag := map[string][]string{}
	for _, r := range releases {
		name := fmt.Sprintf("makima-%s-%s-%s.tar.gz", r.Tag, runtime.GOOS, runtime.GOARCH)
		data := archive(t, r)
		sum := sha256.Sum256(data)
		blobs[r.Tag+"/"+name] = data
		blobs[r.Tag+"/SHA256SUMS"] = []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
		byTag[r.Tag] = []string{name, "SHA256SUMS"}
	}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/repos/justin06lee/makima/releases/"
		switch {
		case strings.HasPrefix(r.URL.Path, prefix):
			which := strings.TrimPrefix(r.URL.Path, prefix)
			tag := strings.TrimPrefix(which, "tags/")
			if which == "latest" && len(releases) > 0 {
				tag = releases[len(releases)-1].Tag
			}
			names, ok := byTag[tag]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			var out []asset
			for _, n := range names {
				out = append(out, asset{Name: n, URL: srv.URL + "/dl/" + tag + "/" + n})
			}
			json.NewEncoder(w).Encode(map[string]any{"tag_name": tag, "assets": out})
		case strings.HasPrefix(r.URL.Path, "/dl/"):
			b, ok := blobs[strings.TrimPrefix(r.URL.Path, "/dl/")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Write(b)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return []subaru.Option{subaru.WithAPIBase(srv.URL), subaru.WithHTTPClient(srv.Client())}
}

func archive(t testing.TB, r Release) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	dir := fmt.Sprintf("makima-%s-%s-%s/", r.Tag, runtime.GOOS, runtime.GOARCH)
	tw.WriteHeader(&tar.Header{Name: dir, Typeflag: tar.TypeDir, Mode: 0o755})
	for name, body := range r.Files {
		if err := tw.WriteHeader(&tar.Header{
			Name: dir + name, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(body)),
			ModTime: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC),
		}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}
