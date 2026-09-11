//go:build windows

package main

import "errors"

func spawnDetached(string, []string, string) error {
	return errors.New("moving from Tailscale is not supported on Windows")
}
