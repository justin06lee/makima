package supervise

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A daemon is "running" when its socket answers, not when a pid exists.
func TestRunningFollowsTheSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "d.sock")

	d := Daemon{Name: "irrelevant", Socket: sock}
	if d.Running() {
		t.Fatal("reported running with nothing listening")
	}

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Running() {
		t.Fatal("reported not running with a live socket")
	}

	ln.Close()
	if d.Running() {
		t.Fatal("reported running after the socket closed")
	}
}

// A socket file left behind by a crash must not read as a live daemon, or
// `makima up` would decide there was nothing to do and leave the node down.
func TestRunningIgnoresAStaleSocketFile(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "stale.sock")

	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if (Daemon{Name: "x", Socket: sock}).Running() {
		t.Fatal("a leftover socket file was mistaken for a running daemon")
	}
}

func TestRunningWithoutASocketIsFalse(t *testing.T) {
	if (Daemon{Name: "x"}).Running() {
		t.Fatal("reported running with no socket configured")
	}
}

// helperDaemon builds a tiny program that listens on a Unix socket and stays
// up until it is signalled.
//
// Compiled rather than improvised out of nc or socat: nc closes after one
// connection, which the liveness probe itself would trigger, and socat is not
// installed everywhere. A real listener is what the supervisor is for, so the
// test uses one.
func helperDaemon(t *testing.T, sock string) string {
	t.Helper()

	src := filepath.Join(t.TempDir(), "main.go")
	code := `package main

import (
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ln, err := net.Listen("unix", os.Args[1])
	if err != nil {
		os.Exit(1)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	<-ch
	ln.Close()
	os.Remove(os.Args[1])
}
`
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	bin := filepath.Join(t.TempDir(), "helperd")
	out, err := exec.Command("go", "build", "-o", bin, src).CombinedOutput()
	if err != nil {
		t.Skipf("cannot build the helper daemon: %v\n%s", err, out)
	}
	return bin
}

// Start brings up a real process and waits for it to answer, and is a no-op
// the second time — which is what makes `makima up` safe to type twice.
func TestStartAndStop(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "t.sock")
	bin := helperDaemon(t, sock)

	d := Daemon{
		Name:    bin,
		Args:    []string{sock},
		Socket:  sock,
		PIDFile: filepath.Join(dir, "t.pid"),
		LogFile: filepath.Join(dir, "t.log"),
	}

	ctx := context.Background()
	if err := d.Start(ctx, 10*time.Second); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !d.Running() {
		t.Fatal("Start returned but the daemon is not answering")
	}
	if _, ok := d.readPID(); !ok {
		t.Fatal("Start recorded no pid")
	}

	// Idempotent: the common case is somebody typing `up` again.
	if err := d.Start(ctx, 10*time.Second); err != nil {
		t.Fatalf("second Start: %v", err)
	}

	if err := d.Stop(ctx, 10*time.Second); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if d.Running() {
		t.Fatal("Stop returned but the daemon is still answering")
	}
	if _, ok := d.readPID(); ok {
		t.Fatal("the pidfile outlived the process")
	}
}

// Stop sends SIGTERM, never SIGKILL: the daemon's shutdown path is what puts
// the routing table, resolver and firewall back, and skipping it leaves a
// machine that blackholes mesh addresses until reboot.
func TestStopLetsTheDaemonCleanUp(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "c.sock")
	bin := helperDaemon(t, sock)

	d := Daemon{
		Name:    bin,
		Args:    []string{sock},
		Socket:  sock,
		PIDFile: filepath.Join(dir, "c.pid"),
		LogFile: filepath.Join(dir, "c.log"),
	}

	ctx := context.Background()
	if err := d.Start(ctx, 10*time.Second); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := d.Stop(ctx, 10*time.Second); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// The helper removes its socket on SIGTERM. Its absence is proof the
	// process ran its shutdown path rather than being killed outright.
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatal("the daemon did not get to clean up after itself")
	}
}

func TestStopWhenNotRunningIsFine(t *testing.T) {
	dir := t.TempDir()
	d := Daemon{
		Name:    "nothing",
		Socket:  filepath.Join(dir, "absent.sock"),
		PIDFile: filepath.Join(dir, "absent.pid"),
	}
	if err := d.Stop(context.Background(), time.Second); err != nil {
		t.Fatalf("stopping an absent daemon: %v", err)
	}
}

func TestStartReportsAMissingBinary(t *testing.T) {
	dir := t.TempDir()
	d := Daemon{
		Name:   "makima-definitely-not-a-real-binary",
		Socket: filepath.Join(dir, "x.sock"),
	}
	err := d.Start(context.Background(), time.Second)
	if err == nil {
		t.Fatal("started a binary that does not exist")
	}
	// The message has to point somewhere useful; "not found in $PATH" alone
	// leaves somebody who has never installed it with nothing to do.
	if !strings.Contains(err.Error(), "make install") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// Pids are reused, so a pidfile naming a dead process must not be trusted into
// signalling whatever now holds that number.
func TestReadPIDRejectsADeadProcess(t *testing.T) {
	dir := t.TempDir()
	pidfile := filepath.Join(dir, "d.pid")

	if err := os.WriteFile(pidfile, []byte("999999"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := (Daemon{PIDFile: pidfile}).readPID(); ok {
		t.Fatal("trusted a pidfile naming a process that does not exist")
	}

	if err := os.WriteFile(pidfile, []byte("not a number"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := (Daemon{PIDFile: pidfile}).readPID(); ok {
		t.Fatal("trusted a pidfile that is not a pid")
	}
}

func TestWritePIDRoundTrip(t *testing.T) {
	dir := t.TempDir()
	d := Daemon{PIDFile: filepath.Join(dir, "sub", "d.pid")}

	d.writePID(os.Getpid())
	got, ok := d.readPID()
	if !ok || got != os.Getpid() {
		t.Fatalf("readPID = %d, %v; want %d, true", got, ok, os.Getpid())
	}

	d.clearPID()
	if _, ok := d.readPID(); ok {
		t.Fatal("pidfile survived clearPID")
	}
}
