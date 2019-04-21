package dhcpv4

import (
	"errors"
	"net"
)

func findSourceIPv4(i *net.Interface) (net.IP, error) {
	addrs, err := i.Addrs()
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("No IP found on interface")
	}

	var pref net.IP
	for _, addr := range addrs {
		net, ok := (addr).(*net.IPNet)
		if !ok {
			continue
		}

		if net.IP.To4() == nil {
			continue
		}

		if pref == nil {
			pref = net.IP
			continue
		}
	}

	return pref, nil
}
