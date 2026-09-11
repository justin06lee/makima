package migrate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Binaries are what a machine needs to be on makima: the CLI finds the other
// three beside itself, so they always travel together.
var Binaries = []string{"makima", "makimad", "makima-server", "makima-relay"}

// Repo is where published releases live.
const Repo = "justin06lee/makima"

// A kit is a release archive: makima-<version>-<os>-<arch>.tar.gz holding one
// directory with the four binaries. The app carries one for every platform
// other than its own as makima-<os>-<arch>.tar.gz, so that moving a Linux
// server from a Mac needs nothing from the internet.
func kitName(goos, goarch string) string { return fmt.Sprintf("makima-%s-%s.tar.gz", goos, goarch) }

// KitDirs are where bundled kits may be.
func KitDirs() []string {
	var dirs []string
	if d := os.Getenv("MAKIMA_KITS"); d != "" {
		dirs = append(dirs, d)
	}
	if exe, err := os.Executable(); err == nil {
		if r, err := filepath.EvalSymlinks(exe); err == nil {
			exe = r
		}
		dir := filepath.Dir(exe)
		dirs = append(dirs,
			filepath.Join(dir, "..", "Resources", "kits"), // inside makima.app
			filepath.Join(dir, "kits"),
		)
	}
	return append(dirs,
		"/usr/lib/makima/kits", // where the Linux packages put the app's resources
		"/usr/local/share/makima/kits",
	)
}

// KitFor finds the four binaries for a platform, as a gzipped tar, and says
// where they came from.
//
// This machine's own binaries when the platforms match — they are the ones
// already running, so the versions agree by construction. A bundled kit next.
// A published release last, and only for a released version, verified against
// its checksums.
func KitFor(ctx context.Context, goos, goarch, version string) ([]byte, string, error) {
	if goos == runtime.GOOS && goarch == runtime.GOARCH {
		if b, dir, err := packOwn(); err == nil {
			return b, "this machine's " + dir, nil
		}
	}
	for _, dir := range KitDirs() {
		p := filepath.Join(dir, kitName(goos, goarch))
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if err := CheckKit(b); err != nil {
			return nil, "", fmt.Errorf("%s: %w", p, err)
		}
		return b, filepath.Clean(p), nil
	}
	if released(version) {
		b, err := download(ctx, goos, goarch, version)
		if err != nil {
			return nil, "", err
		}
		return b, "release " + version, nil
	}
	return nil, "", fmt.Errorf("this copy of makima (%s) carries no build for %s/%s — install the app, which does, or a released version", version, goos, goarch)
}

var releaseTag = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

func released(version string) bool { return releaseTag.MatchString(version) }

// packOwn archives the binaries beside this one.
func packOwn() ([]byte, string, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, "", err
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	dir := filepath.Dir(exe)
	files := map[string][]byte{}
	for _, b := range Binaries {
		data, err := os.ReadFile(filepath.Join(dir, b))
		if err != nil {
			return nil, "", fmt.Errorf("%s is missing beside %s", b, exe)
		}
		files[b] = data
	}
	kit, err := Pack(files)
	return kit, dir, err
}

// Pack makes a kit from the four binaries.
func Pack(files map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range Binaries {
		data, ok := files[name]
		if !ok {
			return nil, fmt.Errorf("%s is missing", name)
		}
		hdr := &tar.Header{Name: "makima/" + name, Mode: 0o755, Size: int64(len(data)), ModTime: time.Now()}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CheckKit makes sure an archive has all four binaries in it.
func CheckKit(kit []byte) error {
	gz, err := gzip.NewReader(bytes.NewReader(kit))
	if err != nil {
		return fmt.Errorf("not a kit: %w", err)
	}
	tr := tar.NewReader(gz)
	found := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("not a kit: %w", err)
		}
		if hdr.Typeflag == tar.TypeReg {
			found[path.Base(hdr.Name)] = true
		}
	}
	for _, b := range Binaries {
		if !found[b] {
			return fmt.Errorf("the kit has no %s in it", b)
		}
	}
	return nil
}

// download fetches a release archive and checks it against SHA256SUMS.
func download(ctx context.Context, goos, goarch, version string) ([]byte, error) {
	name := fmt.Sprintf("makima-%s-%s-%s.tar.gz", version, goos, goarch)
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s/", Repo, version)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	kit, err := fetch(ctx, base+name)
	if err != nil {
		return nil, fmt.Errorf("download makima %s for %s/%s: %w", version, goos, goarch, err)
	}
	sums, err := fetch(ctx, base+"SHA256SUMS")
	if err != nil {
		return nil, fmt.Errorf("download the checksums for %s: %w", version, err)
	}
	sum := sha256.Sum256(kit)
	got := hex.EncodeToString(sum[:])
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			if f[0] != got {
				return nil, fmt.Errorf("%s does not match its published checksum; not installing it", name)
			}
			return kit, CheckKit(kit)
		}
	}
	return nil, fmt.Errorf("%s is not in the release's checksums", name)
}

func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 200<<20))
}

// InstallScript unpacks a kit that has been copied to a machine and puts the
// binaries on PATH. $1 is the kit's path. Run as root.
const InstallScript = `set -e
k="$1"
d=$(mktemp -d)
trap 'rm -rf "$d" "$k"' EXIT
tar -xzf "$k" -C "$d"
mkdir -p /usr/local/bin
for b in makima makimad makima-server makima-relay; do
  f=$(find "$d" -type f -name "$b" | head -n 1)
  [ -n "$f" ] || { echo "the kit has no $b in it" >&2; exit 1; }
  install -m 0755 "$f" "/usr/local/bin/$b"
done
/usr/local/bin/makima version
`

// UploadScript writes stdin to a fresh private file and prints its path.
const UploadScript = `umask 077; t=$(mktemp /tmp/makima-kit.XXXXXX) && cat > "$t" && echo "$t"`
