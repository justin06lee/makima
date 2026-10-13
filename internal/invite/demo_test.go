package invite

import (
	"testing"
	"time"

	"github.com/justin06lee/makima/internal/key"
)

// Shows what somebody actually pastes, and how long it is.
func TestWhatAnInviteLooksLike(t *testing.T) {
	priv, _ := key.NewPrivate()
	// The shape `makima invite` mints: a 24-byte auth key, and the onion
	// address that lets it work from anywhere.
	s, err := Encode(Invite{
		Server:    "http://192.168.1.50:8080",
		AuthKey:   "makima_kQ8xN2vB7wLpR4tYc3VbN6mQ1sZx9aWe",
		ServerKey: priv.Public(),
		Expires:   time.Now().Add(time.Hour),
		Onion:     "aoqqpp7tzyil4hlq3umoos6atft6jvrqtosq2xy53sdgiesvgg4bqead.onion",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d characters:\n  %s", len(s), s)

	// It has to paste in one go, "makima join " and all, on a terminal line
	// of ordinary width — past that it wraps, and somebody copies half of it.
	if len(s) > 320 {
		t.Errorf("an invite is %d characters — too long to paste comfortably", len(s))
	}
}
