package invite

import (
	"strconv"
	"strings"
	"testing"

	"github.com/justin06lee/makima/internal/key"
)

func TestWordsRoundTrip(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	words, err := EncodeWords("http://192.168.1.20:8080", secret)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Fields(words)); n != Words {
		t.Fatalf("got %d words, want %d: %s", n, Words, words)
	}

	inv, ok, err := DecodeWords(words)
	if err != nil || !ok {
		t.Fatalf("DecodeWords: ok=%v err=%v", ok, err)
	}
	if inv.Server != "http://192.168.1.20:8080" {
		t.Errorf("server = %q", inv.Server)
	}
	if string(inv.Secret) != string(secret) {
		t.Errorf("secret did not survive: %x vs %x", inv.Secret, secret)
	}
}

// A machine on a public address on a non-default port, and one on the
// default port: both fit.
func TestWordsCarryThePort(t *testing.T) {
	secret, _ := NewSecret()
	for _, server := range []string{"http://203.0.113.9:9000", "http://203.0.113.9", "http://10.0.0.1:65535"} {
		words, err := EncodeWords(server, secret)
		if err != nil {
			t.Fatal(err)
		}
		inv, ok, err := DecodeWords(words)
		if err != nil || !ok {
			t.Fatalf("%s: ok=%v err=%v", server, ok, err)
		}
		// No port in a URL is port 80 — what the pasted form of the same
		// invite, and every HTTP client, reads it as.
		want := server
		if !strings.Contains(server[len("http://"):], ":") {
			want = server + ":80"
		}
		if inv.Server != want {
			t.Errorf("%s came back as %s", server, inv.Server)
		}
	}
}

// A server behind a name cannot be five words, so the name is typed in front
// of ten.
func TestWordsWithATypedServer(t *testing.T) {
	secret, _ := NewSecret()
	for _, server := range []string{"https://makima.example.dev", "vps.example.com:9000", "vps.example.com"} {
		words, err := EncodeWords(server, secret)
		if err != nil {
			t.Fatal(err)
		}
		if n := len(strings.Fields(words)); n != secretWords+1 {
			t.Fatalf("%s: got %d tokens, want %d: %s", server, n, secretWords+1, words)
		}
		inv, ok, err := DecodeWords(words)
		if err != nil || !ok {
			t.Fatalf("%s: ok=%v err=%v", server, ok, err)
		}
		if string(inv.Secret) != string(secret) {
			t.Errorf("%s: secret did not survive", server)
		}
		if !strings.HasPrefix(inv.Server, "http") {
			t.Errorf("%s: server = %q", server, inv.Server)
		}
	}
	// IPv6 and https addresses take the same road.
	if w, _ := EncodeWords("http://[2001:db8::1]:8080", secret); len(strings.Fields(w)) != secretWords+1 {
		t.Errorf("IPv6 was packed into words: %s", w)
	}
}

// One mistyped word in the address must fail loudly, never dial somebody
// else's machine.
func TestWordsChecksumCatchesATypo(t *testing.T) {
	secret, _ := NewSecret()
	words, _ := EncodeWords("http://192.168.1.20:8080", secret)
	fields := strings.Fields(words)

	caught := 0
	for i := 0; i < addrWords; i++ {
		mutated := append([]string(nil), fields...)
		mutated[i] = Word((wordIndex[fields[i]] + 1) % len(wordList))
		if _, ok, err := DecodeWords(strings.Join(mutated, " ")); !ok || err == nil {
			t.Errorf("word %d changed and nothing noticed", i)
		} else {
			caught++
		}
	}
	if caught != addrWords {
		t.Errorf("caught %d of %d", caught, addrWords)
	}
}

func TestWordsForgiveHowPeopleType(t *testing.T) {
	secret, _ := NewSecret()
	words, _ := EncodeWords("http://192.168.1.20:8080", secret)

	// Capitals, extra spaces, a "makima join" in front, and four-letter
	// prefixes all mean the same fifteen words.
	fields := strings.Fields(words)
	var typed []string
	for _, w := range fields {
		if len(w) > 4 {
			w = w[:4]
		}
		typed = append(typed, strings.ToUpper(w))
	}
	s := "makima join   " + strings.Join(typed, "   ")
	inv, ok, err := DecodeWords(s)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v for %q", ok, err, s)
	}
	if string(inv.Secret) != string(secret) {
		t.Error("secret did not survive being typed as prefixes")
	}
}

func TestDecodeWordsSaysWhatIsWrong(t *testing.T) {
	// Not words at all: the caller should try the other form.
	if _, ok, _ := DecodeWords("mk1_abc"); ok {
		t.Error("a pasted invite was taken for words")
	}
	if _, ok, _ := DecodeWords(""); ok {
		t.Error("nothing was taken for words")
	}

	// Words, but wrong.
	secret, _ := NewSecret()
	words, _ := EncodeWords("http://192.168.1.20:8080", secret)
	fields := strings.Fields(words)

	_, ok, err := DecodeWords(strings.Join(fields[:14], " "))
	if !ok || err == nil || !strings.Contains(err.Error(), "14 words") {
		t.Errorf("fourteen words: ok=%v err=%v", ok, err)
	}
	fields[7] = "zzzzz"
	_, ok, err = DecodeWords(strings.Join(fields, " "))
	if !ok || err == nil || !strings.Contains(err.Error(), `"zzzzz"`) {
		t.Errorf("unknown word: ok=%v err=%v", ok, err)
	}
}

func TestDerivationsAreStableAndDistinct(t *testing.T) {
	secret, _ := NewSecret()
	if Handle(secret) != Handle(secret) || AuthKey(secret) != AuthKey(secret) {
		t.Fatal("derivations are not deterministic")
	}
	if !strings.HasPrefix(AuthKey(secret), "makima_") {
		t.Errorf("auth key %q is not in the usual shape", AuthKey(secret))
	}
	other, _ := NewSecret()
	if Handle(secret) == Handle(other) || AuthKey(secret) == AuthKey(other) {
		t.Fatal("two secrets derived the same thing")
	}
	// Neither the handle nor the auth key gives away the MAC key.
	if strings.Contains(Handle(secret), string(MACKey(secret))) {
		t.Fatal("handle leaks the MAC key")
	}
}

func TestServerKeyMAC(t *testing.T) {
	secret, _ := NewSecret()
	priv, _ := key.NewPrivate()
	mac := ServerKeyMAC(MACKey(secret), priv.Public())
	if !VerifyServerKey(MACKey(secret), priv.Public(), mac) {
		t.Fatal("a genuine MAC failed")
	}
	impostor, _ := key.NewPrivate()
	if VerifyServerKey(MACKey(secret), impostor.Public(), mac) {
		t.Fatal("an impostor's key passed with the real MAC")
	}
	other, _ := NewSecret()
	if VerifyServerKey(MACKey(other), priv.Public(), mac) {
		t.Fatal("a MAC verified under somebody else's words")
	}
}

// A server typed in front of the ten words is the server whatever it is
// called — a machine named after a word ("home"), or a prefix of one
// ("desk"), was taken for a word, and the invite for eleven words.
func TestAServerNamedLikeAWordIsStillTheServer(t *testing.T) {
	secret, _ := NewSecret()
	for _, host := range []string{"home", "desk", "cloud", "tenet"} {
		words, err := EncodeWords("http://"+host+":8081", secret)
		if err != nil {
			t.Fatal(err)
		}
		typed := host + words[strings.Index(words, " "):]
		inv, ok, err := DecodeWords(typed)
		if err != nil || !ok {
			t.Errorf("%s: ok=%v err=%v", host, ok, err)
			continue
		}
		if inv.Server != "http://"+host+":"+strconv.Itoa(DefaultPort) {
			t.Errorf("%s: server %s", host, inv.Server)
		}
	}
}

// The server keeps the case it was typed in: a path behind a reverse proxy
// has one.
func TestTheServerKeepsItsCase(t *testing.T) {
	secret, _ := NewSecret()
	words, err := EncodeWords("https://example.com/Makima", secret)
	if err != nil {
		t.Fatal(err)
	}
	inv, _, err := DecodeWords(words)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Server != "https://example.com/Makima" {
		t.Errorf("server came back as %s", inv.Server)
	}
}
