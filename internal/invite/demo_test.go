package invite

import (
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// Shows what somebody actually pastes, and how long it is.
func TestWhatAnInviteLooksLike(t *testing.T) {
	priv, _ := key.NewPrivate()
	s, err := Encode(Invite{
		Server:    "http://192.168.1.50:8080",
		AuthKey:   "makima_kQ8xN2vB7wLpR4tY",
		ServerKey: priv.Public(),
		Expires:   time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d characters:\n  %s", len(s), s)

	// It has to fit on one terminal line when prefixed with "makima join ",
	// or it wraps and somebody copies half of it.
	if len(s) > 300 {
		t.Errorf("an invite is %d characters — too long to paste comfortably", len(s))
	}
}
