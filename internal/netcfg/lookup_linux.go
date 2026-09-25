package netcfg

import (
	"context"
	"errors"
	"net/netip"
	"os/exec"
)

func routeInterface(ctx context.Context, dst netip.Addr) (string, error) {
	out, err := lookupOutput(ctx, "ip", "-o", "route", "get", dst.String())
	if err != nil {
		return "", err
	}
	if ifc := parseIPRouteGet(out); ifc != "" {
		return ifc, nil
	}
	return "", errors.New("the routing table has no route for " + dst.String())
}

func systemLookup(ctx context.Context, name string) ([]netip.Addr, error) {
	out, err := lookupOutput(ctx, "getent", "ahostsv4", name)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 {
		return nil, nil // getent's "not found"
	}
	if err != nil {
		return nil, err
	}
	return parseGetent(out), nil
}
