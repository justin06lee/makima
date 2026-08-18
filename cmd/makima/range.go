package main

import (
	"net/netip"

	"github.com/justin06lee/makima/internal/netcfg"
)

// netcfgRange is indirected through a function so the CLI does not import a
// mutable package-level variable it might accidentally reassign.
func netcfgRange() netip.Prefix { return netcfg.CGNATRange }
