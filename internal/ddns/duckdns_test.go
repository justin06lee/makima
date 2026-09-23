package ddns

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeDuckDNS answers like DuckDNS does, and records what it was asked.
func fakeDuckDNS(t *testing.T, answer string) *http.Request {
	t.Helper()
	var got http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = *r
		w.Write([]byte(answer))
	}))
	old := Endpoint
	Endpoint = ts.URL + "/update"
	t.Cleanup(func() {
		Endpoint = old
		ts.Close()
	})
	return &got
}

func TestUpdateAsksForTheNameAndLetsDuckDNSSeeTheAddress(t *testing.T) {
	got := fakeDuckDNS(t, "OK\n107.214.144.123\n\nUPDATED")

	r, err := Update(context.Background(), "tenet", "tok-123")
	if err != nil {
		t.Fatal(err)
	}
	if r.IP != "107.214.144.123" || !r.Changed {
		t.Errorf("result = %+v", r)
	}

	q := got.URL.Query()
	if q.Get("domains") != "tenet" || q.Get("token") != "tok-123" || q.Get("verbose") != "true" {
		t.Errorf("asked %v", q)
	}
	// Left blank on purpose: DuckDNS records whatever address the request
	// came from, which is the one the world reaches this machine at.
	if _, set := q["ip"]; !set || q.Get("ip") != "" {
		t.Errorf("ip = %q, want present and blank", q.Get("ip"))
	}
}

func TestAnUnchangedNameIsNotReportedAsAChange(t *testing.T) {
	fakeDuckDNS(t, "OK\n107.214.144.123\n\nNOCHANGE\n")
	r, err := Update(context.Background(), "tenet", "tok")
	if err != nil || r.Changed || r.IP != "107.214.144.123" {
		t.Errorf("result = %+v, %v", r, err)
	}
}

// KO is a wrong name or token, which no amount of retrying fixes, so it has
// to be told apart from a network failure.
func TestARefusalIsRecognised(t *testing.T) {
	fakeDuckDNS(t, "KO")
	if _, err := Update(context.Background(), "tenet", "wrong"); !errors.Is(err, ErrRefused) {
		t.Errorf("err = %v, want ErrRefused", err)
	}
}

// The token travels in the URL, and net/http puts the URL in its errors.
// Nothing that is logged may carry it.
func TestTheTokenNeverAppearsInAnError(t *testing.T) {
	old := Endpoint
	Endpoint = "http://127.0.0.1:1/update"
	t.Cleanup(func() { Endpoint = old })

	_, err := Update(context.Background(), "tenet", "secret-token-value")
	if err == nil {
		t.Fatal("an update to nowhere succeeded")
	}
	if strings.Contains(err.Error(), "secret-token-value") {
		t.Errorf("the token leaked into the error: %v", err)
	}
}

func TestName(t *testing.T) {
	good := map[string]string{
		"tenet":                           "tenet",
		"Tenet.DuckDNS.org":               "tenet",
		"https://tenet.duckdns.org/":      "tenet",
		"tenet.duckdns.org:8080":          "tenet",
		"http://my-home.duckdns.org:8080": "my-home",
	}
	for in, want := range good {
		if got, err := Name(in); err != nil || got != want {
			t.Errorf("Name(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "-tenet", "ten et", "tenet.example.com", "a.b"} {
		if _, err := Name(bad); err == nil {
			t.Errorf("Name(%q) was accepted", bad)
		}
	}
}
