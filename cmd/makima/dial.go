package main

import (
	"net"
	"time"
)

// netDialTimeout is a one-line wrapper so serve.go does not import net just to
// check whether a port answers.
func netDialTimeout(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, time.Second)
}
