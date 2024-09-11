package utils

import "net"

func IsIpLbAddress(x string) bool {
	v := net.ParseIP(x)
	return v != nil && v.To4() != nil && !v.IsUnspecified()
}
