//go:build !darwin

package main

// consoleUID is a macOS notion; nowhere else has one.
func consoleUID() (int, bool) { return 0, false }
