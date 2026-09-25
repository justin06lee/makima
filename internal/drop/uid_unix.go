//go:build unix

package drop

import (
	"os"
	"syscall"
)

// fileUID is the account that owns a file.
func fileUID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
