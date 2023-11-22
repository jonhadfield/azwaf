package policy

import "strings"

func IsIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

func IsIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}
