package commands

import (
	"net/netip"
	"strings"
)

const defaultIPv4Prefix = "/32"

func addrsFromString(in string) (addrs []netip.Prefix, err error) {
	rawAddrs := strings.Split(in, ",")
	for _, rawAddr := range rawAddrs {
		rawAddr = strings.TrimSpace(rawAddr)
		if !strings.Contains(rawAddr, "/") {
			rawAddr += defaultIPv4Prefix
		}

		var addr netip.Prefix

		addr, err = netip.ParsePrefix(rawAddr)
		if err != nil {
			return
		}

		addrs = append(addrs, addr)
	}

	return
}
