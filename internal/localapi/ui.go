package localapi

import (
	"embed"
	"net/http"
	"time"
)

// The UI is one embedded HTML file with its CSS and JavaScript inline, and no
// build step.
//
// A framework would mean a package manager, a bundler, a lockfile, and a
// `dist/` directory in version control — for a page that shows a list of peers
// and a form. It would also break the property that makes this project easy to
// run at all: `go build` produces a working binary on five platforms with no
// other tool installed. Vanilla is not a compromise here, it is the same
// decision as the pure-Go control plane.
//
//go:embed ui/index.html
var uiFS embed.FS

// uiHandler serves the embedded page.
func uiHandler() http.Handler {
	page, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		// Impossible unless the embed directive broke, in which case failing
		// loudly at the one request that needs it beats serving nothing with
		// no explanation.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "ui: "+err.Error(), http.StatusInternalServerError)
		})
	}

	// A fixed modification time so conditional requests work and the page is
	// not re-sent on every poll. The build is the only thing that changes it.
	modTime := time.Time{}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The page reconfigures a VPN. Keeping it out of shared caches costs
		// nothing at this size.
		w.Header().Set("Cache-Control", "no-store")
		http.ServeContent(w, r, "index.html", modTime, newReader(page))
	})
}
