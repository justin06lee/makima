package bypass

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestOnionAddressesGoToTor(t *testing.T) {
	var asked []string
	b := &Binder{}
	b.SetOnion(func(ctx context.Context, network, address string) (net.Conn, error) {
		asked = append(asked, address)
		return nil, errors.New("tor stand-in")
	})
	const onion = "aoqqpp7tzyil4hlq3umoos6atft6jvrqtosq2xy53sdgiesvgg4bqead.onion:80"
	d := &net.Dialer{Timeout: time.Second}
	if _, err := b.DialContext(context.Background(), d, "tcp", onion); err == nil || err.Error() != "tor stand-in" {
		t.Fatalf("onion dial: %v", err)
	}
	if len(asked) != 1 || asked[0] != onion {
		t.Fatalf("tor was asked for %v", asked)
	}

	// Everything else dials as it always did.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := b.DialContext(context.Background(), d, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if len(asked) != 1 {
		t.Errorf("a loopback dial went to tor: %v", asked)
	}
}

func TestNilBinderHasNoOnionRoute(t *testing.T) {
	var b *Binder
	if b.onionDialer("aoqqpp7tzyil4hlq3umoos6atft6jvrqtosq2xy53sdgiesvgg4bqead.onion:80") != nil {
		t.Fatal("a nil binder found an onion route")
	}
}
