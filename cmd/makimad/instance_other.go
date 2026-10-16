//go:build !unix

package main

// holdInstance has no flock to stand on here; a second daemon finds out the
// old way, when its port is taken.
func holdInstance(string) {}
