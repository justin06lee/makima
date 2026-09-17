package sshd

import (
	"encoding/json"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Answering "which accounts does my key open here?".
//
// A connection under ListAccountsUser never reaches a process. It is given one
// JSON object and closed, which is the whole of what that username can do —
// so the question can be asked before anybody has decided which account to
// become, without the asking itself being a way in.

// encodeAccount packs one account into the string ssh.Permissions can carry.
// Two fields and a fixed separator rather than JSON, because this crosses only
// from the handshake to the channel loop a few lines later.
func encodeAccount(a Account) string {
	flags := ""
	if a.Default {
		flags += "d"
	}
	if a.Root {
		flags += "r"
	}
	return flags + " " + a.Name
}

// decodeAccounts unpacks what encodeAccount wrote.
func decodeAccounts(s string) []Account {
	var out []Account
	for _, line := range strings.Split(s, "\n") {
		flags, name, ok := strings.Cut(line, " ")
		if !ok || name == "" {
			continue
		}
		out = append(out, Account{
			Name:    name,
			Default: strings.Contains(flags, "d"),
			Root:    strings.Contains(flags, "r"),
		})
	}
	return out
}

// answerAccounts writes the list and closes the session.
//
// Replies true to shell and exec alike: a client that asked this username for
// anything at all is asking the one question this username answers, and
// failing its request would only make it report a shell that would not start.
func answerAccounts(nch ssh.NewChannel, encoded string) {
	ch, reqs, err := nch.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	body, err := json.Marshal(AccountList{Accounts: decodeAccounts(encoded)})
	if err != nil {
		sendExitStatus(ch, 1)
		return
	}

	for req := range reqs {
		switch req.Type {
		case "shell", "exec":
			req.Reply(true, nil)
			_, _ = ch.Write(append(body, '\n'))
			sendExitStatus(ch, 0)
			return
		case "pty-req":
			// No process, so nothing to attach a terminal to.
			req.Reply(false, nil)
		default:
			req.Reply(false, nil)
		}
	}
}
