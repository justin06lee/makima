package invite

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/justin06lee/makima/internal/key"
)

// Fifteen words.
//
// The mk1_ string is right for a paste and wrong for a keyboard: a hundred and
// fifty characters of base64 is not something anybody types into a laptop
// that is not on the network yet. Fifteen English words are — the same idea
// as a recovery phrase, for the same reason.
//
// Fifteen words carry 165 bits. Five of them say where the server is — an
// IPv4 address and a port, with a checksum so a mistyped word fails at once
// rather than dialling a stranger — and ten are a secret that only the
// machine holding the network knows. That secret is not the credential
// itself: the credential, a lookup handle and a verification key are all
// derived from it, and the server stores those, never the words. When the
// joining machine asks the server for its public key it sends the handle, and
// the server answers with the key and a MAC over it under the verification
// key. An impostor between the two can relay that answer but cannot forge one
// for a key of its own, which is what the mk1_ form carried the server key
// in the string to prevent — and what these words achieve without the room.
//
// A server behind a name rather than an address cannot be written in five
// words; for that case the words are ten and the name is typed in front.
//
// The words are the BIP39 English list: two thousand and forty-eight of them,
// each unique in its first four letters, chosen for exactly this job.

//go:embed english.txt
var wordlistText string

var (
	wordList  []string
	wordIndex map[string]int
)

func init() {
	wordList = strings.Fields(wordlistText)
	if len(wordList) != 1<<wordBits {
		panic(fmt.Sprintf("invite: wordlist has %d words, want %d", len(wordList), 1<<wordBits))
	}
	wordIndex = make(map[string]int, len(wordList))
	for i, w := range wordList {
		wordIndex[w] = i
	}
}

const (
	wordBits = 11

	// addrWords carry an IPv4 address, a port, and a seven-bit checksum.
	addrWords = 5
	addrBits  = addrWords * wordBits // 55
	checkBits = addrBits - 32 - 16   // 7

	// secretWords carry the secret.
	secretWords = 10
	secretBits  = secretWords * wordBits // 110
	secretBytes = 14                     // 112 bits; the top two are zero

	// Words is how many a full invite has.
	Words = addrWords + secretWords
)

// Word is one entry of the list, by position.
func Word(i int) string { return wordList[i] }

// NewSecret draws the ten words' worth of randomness.
func NewSecret() ([]byte, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("invite: read entropy: %w", err)
	}
	b[0] &= 0x3f
	return b, nil
}

// Handle is the lookup key the joining machine sends. Public: it identifies
// the invite without revealing the words.
func Handle(secret []byte) string {
	sum := sha256.Sum256(append([]byte("makima-invite-handle\x00"), secret...))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// AuthKey is the credential the server stores and the joiner presents, in
// the same shape as every other auth key.
func AuthKey(secret []byte) string {
	sum := sha256.Sum256(append([]byte("makima-invite-auth\x00"), secret...))
	return "makima_" + base64.RawURLEncoding.EncodeToString(sum[:24])
}

// MACKey is what the server uses to vouch for its own public key to a
// machine holding the words.
func MACKey(secret []byte) []byte {
	sum := sha256.Sum256(append([]byte("makima-invite-mac\x00"), secret...))
	return sum[:]
}

// ServerKeyMAC is the server's proof that a key is its own, to somebody who
// holds the words.
func ServerKeyMAC(macKey []byte, k key.Public) []byte {
	m := hmac.New(sha256.New, macKey)
	m.Write(k[:])
	return m.Sum(nil)
}

// VerifyServerKey checks that proof.
func VerifyServerKey(macKey []byte, k key.Public, mac []byte) bool {
	return hmac.Equal(ServerKeyMAC(macKey, k), mac)
}

// EncodeWords renders where the server is and the secret as words.
//
// Fifteen when the server is reachable at an IPv4 address over plain HTTP;
// otherwise the server as given, followed by ten words.
func EncodeWords(server string, secret []byte) (string, error) {
	if len(secret) != secretBytes || secret[0]&0xc0 != 0 {
		return "", errors.New("invite: secret is not ten words' worth")
	}
	sec := new(big.Int).SetBytes(secret)

	if ip, port, ok := ipv4Server(server); ok {
		v := new(big.Int).SetUint64(addrValue(ip, port))
		v.Lsh(v, secretBits)
		v.Or(v, sec)
		return strings.Join(toWords(v, Words), " "), nil
	}

	where := strings.TrimRight(strings.TrimSpace(server), "/")
	if where == "" {
		return "", errors.New("invite: no server")
	}
	return where + " " + strings.Join(toWords(sec, secretWords), " "), nil
}

// WordInvite is what the words said.
type WordInvite struct {
	// Server is where the joining machine reaches the network's server.
	Server string
	// Secret is the ten words' worth of randomness.
	Secret []byte
}

// DecodeWords reads an invite typed as words.
//
// ok is false when the text does not look like words at all — so a caller
// can try the other form — and err says what is wrong when it does.
func DecodeWords(s string) (inv WordInvite, ok bool, err error) {
	tokens := strings.Fields(strings.ToLower(strings.TrimSpace(s)))
	// "makima join" typed or pasted in front is a habit, not a mistake.
	if len(tokens) >= 2 && tokens[0] == "makima" && (tokens[1] == "join" || tokens[1] == "up") {
		tokens = tokens[2:]
	}
	if len(tokens) < 2 {
		return WordInvite{}, false, nil
	}

	// Ten words after a typed server, or fifteen words.
	if _, isWord := lookup(tokens[0]); !isWord && len(tokens) == secretWords+1 {
		sec, err := fromWords(tokens[1:])
		if err != nil {
			return WordInvite{}, true, err
		}
		return WordInvite{Server: serverURL(tokens[0]), Secret: sec.FillBytes(make([]byte, secretBytes))}, true, nil
	}

	if len(tokens) != Words {
		if _, isWord := lookup(tokens[0]); !isWord && !looksLikeWords(tokens) {
			return WordInvite{}, false, nil
		}
		return WordInvite{}, true, fmt.Errorf("invite: %d words, but an invite is %d (or a server followed by %d)", len(tokens), Words, secretWords)
	}

	v, err := fromWords(tokens)
	if err != nil {
		return WordInvite{}, true, err
	}
	mask := new(big.Int).Lsh(big.NewInt(1), secretBits)
	mask.Sub(mask, big.NewInt(1))
	sec := new(big.Int).And(v, mask)
	addr := new(big.Int).Rsh(v, secretBits).Uint64()

	ip, port, ok := splitAddrValue(addr)
	if !ok {
		return WordInvite{}, true, errors.New("invite: the first five words do not add up — one of them is probably mistyped")
	}
	return WordInvite{
		Server: "http://" + net.JoinHostPort(ip.String(), strconv.Itoa(int(port))),
		Secret: sec.FillBytes(make([]byte, secretBytes)),
	}, true, nil
}

// looksLikeWords reports whether most tokens are words, so a mistyped word
// list is reported as such rather than dismissed as "not an invite".
func looksLikeWords(tokens []string) bool {
	n := 0
	for _, t := range tokens {
		if _, ok := lookup(t); ok {
			n++
		}
	}
	return n*2 >= len(tokens)
}

// ipv4Server reports whether a server URL is a plain-HTTP IPv4 address.
func ipv4Server(server string) (netip.Addr, uint16, bool) {
	u, err := url.Parse(strings.TrimSpace(server))
	if err != nil || u.Scheme != "http" || u.Path != "" && u.Path != "/" {
		return netip.Addr{}, 0, false
	}
	host := u.Hostname()
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return netip.Addr{}, 0, false
	}
	port := 8080
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil || port <= 0 || port > 65535 {
			return netip.Addr{}, 0, false
		}
	}
	return ip, uint16(port), true
}

// serverURL turns what somebody typed in front of the words into a URL.
func serverURL(s string) string {
	s = strings.TrimRight(s, "/")
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return s
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return "http://" + s
	}
	return "http://" + net.JoinHostPort(s, "8080")
}

// addrValue packs an address, a port and a checksum into 55 bits.
func addrValue(ip netip.Addr, port uint16) uint64 {
	b := ip.As4()
	v := uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
	v = v<<16 | uint64(port)
	return v<<checkBits | uint64(checksum(ip, port))
}

func splitAddrValue(v uint64) (netip.Addr, uint16, bool) {
	check := uint8(v & (1<<checkBits - 1))
	v >>= checkBits
	port := uint16(v & 0xffff)
	v >>= 16
	ip := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	if checksum(ip, port) != check {
		return netip.Addr{}, 0, false
	}
	return ip, port, true
}

func checksum(ip netip.Addr, port uint16) uint8 {
	b := ip.As4()
	sum := sha256.Sum256([]byte{b[0], b[1], b[2], b[3], byte(port >> 8), byte(port)})
	return sum[0] >> (8 - checkBits)
}

// toWords writes v as n words, most significant first.
func toWords(v *big.Int, n int) []string {
	out := make([]string, n)
	mask := big.NewInt(1<<wordBits - 1)
	for i := n - 1; i >= 0; i-- {
		d := new(big.Int).And(v, mask)
		out[i] = wordList[d.Int64()]
		v = new(big.Int).Rsh(v, wordBits)
	}
	return out
}

// fromWords reads words back into a number, naming the first one it does not
// know.
func fromWords(words []string) (*big.Int, error) {
	v := new(big.Int)
	for _, w := range words {
		i, ok := lookup(w)
		if !ok {
			return nil, fmt.Errorf("invite: %q is not one of the words — check the spelling", w)
		}
		v.Lsh(v, wordBits)
		v.Or(v, big.NewInt(int64(i)))
	}
	return v, nil
}

// lookup finds a word, or the one word a typed prefix of four or more
// letters can only mean. Every word on the list is unique in its first four
// letters, which is what makes typing "abst" for "abstract" safe.
func lookup(w string) (int, bool) {
	if i, ok := wordIndex[w]; ok {
		return i, true
	}
	if len(w) < 4 {
		return 0, false
	}
	found, at := false, 0
	for i, cand := range wordList {
		if strings.HasPrefix(cand, w) {
			if found {
				return 0, false
			}
			found, at = true, i
		}
	}
	return at, found
}
