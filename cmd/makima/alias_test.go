package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The file has to be the one the shell reads, chosen by what exists rather
// than by $SHELL — under sudo $SHELL is often root's, and that is the only
// path this is ever taken from.
func TestShellStartupFile(t *testing.T) {
	t.Run("prefers zsh when both exist", func(t *testing.T) {
		home := t.TempDir()
		touch(t, filepath.Join(home, ".bashrc"))
		touch(t, filepath.Join(home, ".zshrc"))

		got, ok := shellStartupFile(home)
		if !ok || filepath.Base(got) != ".zshrc" {
			t.Fatalf("got %q, want .zshrc", got)
		}
	})

	t.Run("falls back through the list", func(t *testing.T) {
		home := t.TempDir()
		touch(t, filepath.Join(home, ".profile"))

		got, ok := shellStartupFile(home)
		if !ok || filepath.Base(got) != ".profile" {
			t.Fatalf("got %q, want .profile", got)
		}
	})

	t.Run("says so when there is nothing to write to", func(t *testing.T) {
		if _, ok := shellStartupFile(t.TempDir()); ok {
			t.Fatal("found a startup file in an empty home directory")
		}
	})
}

// Running `up` twice is normal, and the second time must not add the alias
// again — a shell config that grows a duplicate block per invocation is a
// mess somebody else has to clean up.
func TestAppendAliasBlockIsIdempotent(t *testing.T) {
	rc := filepath.Join(t.TempDir(), ".zshrc")
	touch(t, rc)

	added, err := appendAliasBlock(rc)
	if err != nil || !added {
		t.Fatalf("first append: added=%v err=%v", added, err)
	}

	added, err = appendAliasBlock(rc)
	if err != nil {
		t.Fatalf("second append: %v", err)
	}
	if added {
		t.Fatal("added the block a second time")
	}

	got := read(t, rc)
	if n := strings.Count(got, aliasBegin); n != 1 {
		t.Fatalf("the marker appears %d times:\n%s", n, got)
	}
	if !strings.Contains(got, "# existing config") {
		t.Fatal("clobbered what was already in the file")
	}
}

// A startup file that does not exist yet is created rather than skipped.
func TestAppendAliasBlockCreatesTheFile(t *testing.T) {
	rc := filepath.Join(t.TempDir(), ".zshrc")

	added, err := appendAliasBlock(rc)
	if err != nil || !added {
		t.Fatalf("added=%v err=%v", added, err)
	}
	if !strings.Contains(read(t, rc), aliasBody) {
		t.Fatal("the alias is not in the file")
	}
}

// The alias itself has to survive a shell parsing it, and has to be the thing
// the user asked for rather than something adjacent.
func TestAliasBody(t *testing.T) {
	if !strings.Contains(aliasBody, "die") {
		t.Fatalf("the alias is not called die: %q", aliasBody)
	}
	if !strings.Contains(aliasBody, "makima down") {
		t.Fatalf("die does not stop the mesh: %q", aliasBody)
	}
	// Root is needed to take the interface down, and an alias that fails with
	// a permission error is worse than no alias.
	if !strings.Contains(aliasBody, "sudo") {
		t.Fatalf("die will fail without root: %q", aliasBody)
	}
	if strings.Contains(aliasBody, "\n") {
		t.Fatal("the alias spans lines, which will not survive being sourced")
	}
}

// A block written under sudo has to be findable and removable by hand, which
// means both fences have to be there.
func TestAliasBlockIsFenced(t *testing.T) {
	home := t.TempDir()
	rc := filepath.Join(home, ".zshrc")
	touch(t, rc)
	writeAliasBlock(t, rc)

	got := read(t, rc)
	if !strings.Contains(got, aliasBegin) || !strings.Contains(got, aliasEnd) {
		t.Fatalf("the block is not fenced at both ends:\n%s", got)
	}
	if strings.Index(got, aliasBegin) > strings.Index(got, aliasEnd) {
		t.Fatal("the fences are the wrong way round")
	}
}

func TestInvokingUserIgnoresRoot(t *testing.T) {
	t.Setenv("SUDO_USER", "root")
	if _, ok := invokingUser(); ok && os.Geteuid() == 0 {
		t.Fatal("resolved a user to write to when sudo came from root itself")
	}
}

func writeAliasBlock(t *testing.T, rc string) {
	t.Helper()
	if _, err := appendAliasBlock(rc); err != nil {
		t.Fatal(err)
	}
}

func touch(t *testing.T, p string) {
	t.Helper()
	if err := os.WriteFile(p, []byte("# existing config\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
