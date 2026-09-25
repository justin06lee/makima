//go:build !darwin && !linux

package netcfg

import (
	"context"
	"net/netip"
)

func routeInterface(ctx context.Context, dst netip.Addr) (string, error) { return "", ErrNoLookup }

func systemLookup(ctx context.Context, name string) ([]netip.Addr, error) { return nil, ErrNoLookup }
