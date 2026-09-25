package netcfg

import (
	"context"
	"errors"
	"net/netip"
)

func routeInterface(ctx context.Context, dst netip.Addr) (string, error) {
	out, err := lookupOutput(ctx, "route", "-n", "get", dst.String())
	if err != nil {
		return "", err
	}
	if ifc := parseRouteGet(out); ifc != "" {
		return ifc, nil
	}
	return "", errors.New("the routing table has no route for " + dst.String())
}

func systemLookup(ctx context.Context, name string) ([]netip.Addr, error) {
	out, err := lookupOutput(ctx, "dscacheutil", "-q", "host", "-a", "name", name)
	if err != nil {
		return nil, err
	}
	return parseDscacheutil(out), nil
}
