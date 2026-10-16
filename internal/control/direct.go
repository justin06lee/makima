package control

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"time"

	"github.com/justin06lee/makima/internal/tor"
)

// Which of the control plane's addresses a node uses.
//
// Direct ones first, the onion address last: tor is how a node away from
// home reaches the server at all, and the slowest, flakiest way to reach one
// it could have reached directly. A node that fell back to the onion keeps
// looking for a direct address in the background and moves the moment one
// answers; the machine holding the network reaches its own server over
// loopback and never through tor.

// probeTimeout bounds asking one address whether this control plane is
// there. A variable for the tests.
var probeTimeout = dialTimeout

// upgradeEvery is how often a client on anything but its best address looks
// for a better one that answers.
const upgradeEvery = 30 * time.Second

// localPatience is how long a node that has reached its control plane on its
// own machine waits for it to answer there again before trying tor, which
// leads back to the same server. Only for a server that has gone for good —
// moved to another machine — not one restarting for an update.
const localPatience = 10 * time.Minute

// errMoved ends a poll held open at one address when a better one answered,
// so that it is sent again there.
var errMoved = errors.New("the control plane answered at a better address")

// ownAddress reports whether this machine holds an address. A variable for
// the tests.
var ownAddress = func(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() {
		return true
	}
	held, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, h := range held {
		if p, err := netip.ParsePrefix(h.String()); err == nil && p.Addr().Unmap() == a {
			return true
		}
	}
	return false
}

// rank orders a control plane's addresses, best first:
//
//  0. on this machine, over loopback: where it answered before (local), and
//     loopback in place of any address of this machine's own;
//  1. the server's own LAN addresses, as it names them;
//  2. the address the node joined through — after those, because it is
//     the one that goes stale when the server's DHCP lease moves, and
//     ahead of the rest, as it always was with a server that names none;
//  3. any other name or address;
//  4. onion addresses.
//
// Within each, the server's order, then the joined one.
func rank(joined string, alts []string, local string) []string {
	type cand struct {
		u     string
		class int
	}
	var cs []cand
	add := func(u string, class int) {
		if u != "" && !slices.ContainsFunc(cs, func(c cand) bool { return c.u == u }) {
			cs = append(cs, cand{u, class})
		}
	}
	add(local, 0)
	for _, u := range append(slices.Clone(alts), joined) {
		add(loopbackFor(u), 0)
	}
	for _, u := range alts {
		add(u, classOf(u, false))
	}
	add(joined, classOf(joined, true))
	slices.SortStableFunc(cs, func(a, b cand) int { return cmp.Compare(a.class, b.class) })

	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.u
	}
	return out
}

// classOf is rank's class for one address.
func classOf(raw string, joined bool) int {
	p, err := url.Parse(raw)
	if err != nil {
		return 3
	}
	host := p.Hostname()
	if tor.IsOnion(host) {
		return 4
	}
	if host == "localhost" {
		return 0
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		switch {
		case ip.IsLoopback():
			return 0
		case ownAddress(ip):
			return 1
		case !joined && (ip.IsPrivate() || ip.IsLinkLocalUnicast()):
			return 1
		}
	}
	if joined {
		return 2
	}
	return 3
}

// loopbackFor is the loopback address to try for a control URL naming this
// machine, or "".
func loopbackFor(raw string) string {
	p, err := url.Parse(raw)
	if err != nil || p.Scheme != "http" {
		// https to 127.0.0.1 would not match the certificate.
		return ""
	}
	host := p.Hostname()
	if host == "localhost" {
		return raw
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ownAddress(ip) {
		return ""
	}
	if ip.Unmap().IsLoopback() {
		return raw
	}
	port := p.Port()
	if port == "" {
		port = "80"
	}
	p.Host = net.JoinHostPort("127.0.0.1", port)
	return p.String()
}

// isLoopbackURL reports whether a control URL is on this machine's loopback.
func isLoopbackURL(raw string) bool {
	p, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if p.Hostname() == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(p.Hostname())
	return err == nil && ip.Unmap().IsLoopback()
}

// answered records that u answered a request that started at start.
func (c *Client) answered(start, u string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if isLoopbackURL(u) {
		c.localDown = time.Time{}
		if c.local != u {
			c.local = u
			c.rerankLocked()
		}
	}
	// Not over a better address something else moved to meanwhile — the
	// look for one, while this poll was held open at a worse one.
	if c.cur == "" || c.cur == start || c.rankOf(u) < c.rankOf(c.cur) {
		c.cur = u
	}
}

// failed records that u did not answer.
func (c *Client) failed(u string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Not in use any more: a poll that fell back to a worse address is not
	// moved straight back to it.
	if c.cur == u {
		c.cur = ""
	}
	if u != c.local {
		return
	}
	switch {
	case c.localDown.IsZero():
		c.localDown = time.Now()
	case time.Since(c.localDown) >= localPatience:
		c.local, c.localDown = "", time.Time{}
		c.rerankLocked()
	}
}

// rankOf is u's place in urls, or past the end for one not there.
func (c *Client) rankOf(u string) int {
	if i := slices.Index(c.urls, u); i >= 0 {
		return i
	}
	return len(c.urls)
}

// candidates are the addresses to try, in order, after exclude did not
// answer, and why each left out was.
//
// The direct ones are asked first, all at once, whether this control plane
// is there; only those it answered at are tried, which makes a laptop that
// has left the house wait out one connection timeout rather than one for
// each address it knows at home. The onion ones follow untried — asking one
// costs as much as using it — except on the machine holding the network,
// whose way to its own server is loopback and never tor.
func (c *Client) candidates(ctx context.Context, exclude string) (order, unanswered []string) {
	c.mu.Lock()
	urls := slices.Clone(c.urls)
	holder := c.local != "" && (c.localDown.IsZero() || time.Since(c.localDown) < localPatience)
	c.mu.Unlock()

	var direct, onion []string
	for _, u := range urls {
		switch {
		case u == exclude:
		case isOnionURL(u):
			if !holder {
				onion = append(onion, u)
			}
		default:
			direct = append(direct, u)
		}
	}
	if len(direct) > 1 {
		var failed []string
		direct, unanswered, failed = c.probe(ctx, direct)
		for _, u := range failed {
			c.failed(u)
		}
	}
	return append(direct, onion...), unanswered
}

// probe asks each address, at once, whether this control plane is there,
// and returns those it is at, in the order given — once the best possible
// answer is in, without waiting out the rest — with why each other did not.
func (c *Client) probe(ctx context.Context, urls []string) (ok, unanswered, failed []string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		i   int
		err error
	}
	results := make(chan result, len(urls))
	for i, u := range urls {
		go func() { results <- result{i, c.knows(ctx, u)} }()
	}
	done := make([]bool, len(urls))
	errs := make([]error, len(urls))
	for range urls {
		r := <-results
		done[r.i], errs[r.i] = true, r.err
		if settled(done, errs) {
			break
		}
	}
	for i, u := range urls {
		switch {
		case !done[i]:
		case errs[i] == nil:
			ok = append(ok, u)
		default:
			unanswered = append(unanswered, fmt.Sprintf("%s: %v", u, errs[i]))
			failed = append(failed, u)
		}
	}
	return ok, unanswered, failed
}

// settled reports whether some address has answered and every one ahead of
// it has finished.
func settled(done []bool, errs []error) bool {
	for i := range done {
		if !done[i] {
			return false
		}
		if errs[i] == nil {
			return true
		}
	}
	return true
}

// knows asks the address whether this control plane is there: whether it
// hands out this control plane's key.
//
// Only a hint — the key is public, and anybody can repeat it. What proves an
// answer came from the control plane is still that it opens under the key,
// and an address that passes here and then fails that is passed over all the
// same.
func (c *Client) knows(ctx context.Context, base string) error {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	u, err := url.JoinPath(base, "key")
	if err != nil {
		return fmt.Errorf("build key URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("reach control server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("asked for its key: %s", resp.Status)
	}
	var kr keyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&kr); err != nil {
		return fmt.Errorf("asked for its key: %w", err)
	}
	if kr.Version != ProtocolVersion || kr.ServerKey != c.serverKey {
		return errors.New("another server answers there")
	}
	return nil
}

// lookForBetter looks, in the background, for an address better than the one
// in use that answers — and moves there, polls held open included — when it
// is time to.
//
// This is what takes a node off tor: it fell back to the onion address in a
// café, or before the server had named its LAN address, and it comes back to
// a direct one as soon as one answers rather than at the next network change.
func (c *Client) lookForBetter() {
	c.mu.Lock()
	from := c.cur
	i := slices.Index(c.urls, from)
	var better []string
	if i > 0 {
		for _, u := range c.urls[:i] {
			if !isOnionURL(u) {
				better = append(better, u)
			}
		}
	}
	if c.probing || len(better) == 0 || time.Since(c.probed) < upgradeEvery {
		c.mu.Unlock()
		return
	}
	c.probing = true
	c.mu.Unlock()

	go func() {
		ok, _, _ := c.probe(context.Background(), better)

		c.mu.Lock()
		c.probing = false
		c.probed = time.Now()
		if len(ok) == 0 || (c.cur != "" && c.rankOf(ok[0]) >= c.rankOf(c.cur)) {
			c.mu.Unlock()
			return
		}
		c.cur = ok[0]
		var move []*parkedPoll
		for p := range c.parked {
			if c.rankOf(p.base) > c.rankOf(c.cur) {
				move = append(move, p)
			}
		}
		c.mu.Unlock()
		for _, p := range move {
			p.cancel(errMoved)
		}
	}()
}

// parkedPoll is a poll held open at one address.
type parkedPoll struct {
	base   string
	cancel context.CancelCauseFunc
}

// park records a poll held open at base, until done.
func (c *Client) park(ctx context.Context, base string) (context.Context, func()) {
	pctx, cancel := context.WithCancelCause(ctx)
	p := &parkedPoll{base: base, cancel: cancel}
	c.mu.Lock()
	c.parked[p] = struct{}{}
	// A better address may have answered between this poll choosing base
	// and getting here.
	if c.cur != "" && c.rankOf(c.cur) < c.rankOf(base) {
		cancel(errMoved)
	}
	c.mu.Unlock()
	return pctx, func() {
		c.mu.Lock()
		delete(c.parked, p)
		c.mu.Unlock()
		cancel(nil)
	}
}
