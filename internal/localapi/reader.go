package localapi

import "bytes"

// newReader adapts a byte slice to what http.ServeContent needs, which is a
// ReadSeeker rather than a Reader — it seeks to determine length and to answer
// range requests.
func newReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
