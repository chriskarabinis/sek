// Package netx holds the name resolution shared by the commands that need a
// single address for a target.
package netx

import (
	"context"
	"fmt"
	"net"
)

// ResolvePreferIPv4 returns target unchanged when it is already an IP address,
// otherwise resolves it and prefers an IPv4 answer.
//
// It goes through net.Resolver.LookupHost rather than net.LookupHost so the
// caller's context applies: without one, cancelling a command left it sitting
// out the full DNS timeout before it could return.
func ResolvePreferIPv4(ctx context.Context, target string) (string, error) {
	if net.ParseIP(target) != nil {
		return target, nil
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, target)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("cannot resolve: %s", target)
	}
	for _, addr := range addrs {
		if net.ParseIP(addr).To4() != nil {
			return addr, nil
		}
	}
	return addrs[0], nil
}
