package commands

import (
	"net/netip"
	"strings"
)

func addrsFromString(in string) (addrs []netip.Prefix, err error) {
	rawAddrs := strings.Split(in, ",")
	for _, rawAddr := range rawAddrs {
		rawAddr = strings.TrimSpace(rawAddr)
		if !strings.Contains(rawAddr, "/") {
			rawAddr += "/32"
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
