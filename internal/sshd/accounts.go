package sshd

import "strings"

// Accounts is the set of local accounts a session may run as.
//
// An interface so the server can be tested without a machine full of real
// users, and so the one place that decides "this key may become this account"
// is separable from the one that reads the machine's password database.
type Accounts interface {
	// Lookup resolves one account by name. It returns an error for a name
	// that is not a local account, or is one nobody can log in as.
	Lookup(name string) (*SessionUser, error)

	// List is every account somebody could log in as, in no order.
	List() ([]*SessionUser, error)

	// Keys is the account's own authorized_keys — the file its owner controls
	// and the system's sshd already honours. Reading it is what makes "you may
	// become root here" a decision this machine's administrator made, rather
	// than one makima made for them.
	Keys(u *SessionUser) ([]AuthorizedKey, error)
}

// nonLoginShells are the shells that exist to refuse a login.
//
// Matched on the base name, so /sbin/nologin, /usr/sbin/nologin and
// /usr/bin/false are all the same answer.
var nonLoginShells = map[string]bool{
	"nologin":  true,
	"false":    true,
	"true":     true,
	"sync":     true,
	"shutdown": true,
	"halt":     true,
}

// canLogIn reports whether a shell is one a person could get a session on.
func canLogIn(shell string) bool {
	if shell == "" {
		return false
	}
	if i := strings.LastIndexByte(shell, '/'); i >= 0 {
		shell = shell[i+1:]
	}
	return !nonLoginShells[shell]
}

// AccountList is what a client is told when it asks which accounts its key
// opens. Sorted by SortAccounts before it goes out.
type AccountList struct {
	Accounts []Account `json:"accounts"`
}

// Account is one entry in that answer.
type Account struct {
	Name string `json:"name"`

	// Default marks the account a session runs as when the client names none —
	// the one `makima sshd` was pointed at.
	Default bool `json:"default,omitempty"`

	// Root marks uid 0, so a client can say so without knowing unix.
	Root bool `json:"root,omitempty"`
}

// SortAccounts puts the list in the order somebody would want to see it: the
// machine's own account first, root last, everything else alphabetically
// between them.
//
// Not cosmetic. This order is what a picker's cursor starts on, and starting
// it on root would make the most dangerous choice the easiest one.
func SortAccounts(in []Account) []Account {
	rank := func(a Account) int {
		switch {
		case a.Default:
			return 0
		case a.Root:
			return 2
		default:
			return 1
		}
	}
	out := append([]Account(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			a, b := out[j-1], out[j]
			if rank(a) < rank(b) || (rank(a) == rank(b) && a.Name <= b.Name) {
				break
			}
			out[j-1], out[j] = b, a
		}
	}
	return out
}
