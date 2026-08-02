// Package netx holds the network helpers shared by the scanning packages.
package netx

import (
	"context"
	"fmt"
	"net"
)

// ResolveIP turns a target into a single address, preferring IPv4 because the
// services being probed are far more likely to be reachable over it.
//
// It resolves through the context-aware resolver. net.LookupHost takes no
// context, so an interrupted command sat through the full DNS timeout before it
// could return, and the ctx every caller already threads down was ignored.
func ResolveIP(ctx context.Context, target string) (string, error) {
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
