//go:build !unix

package drop

import "os"

// fileUID is unknown here, so no link out of a home is ever followed.
func fileUID(fi os.FileInfo) (int, bool) { return 0, false }
