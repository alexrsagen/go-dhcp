package dhcpv4

import (
	"errors"
	"fmt"
	"net"
)

func findSourceIPv4(i *net.Interface) (net.IP, error) {
	addrs, err := i.Addrs()
	if err != nil {
		return nil, fmt.Errorf("net.Interface.Addrs: %v", err)
	}
	if len(addrs) == 0 {
		return nil, errors.New("No IP found on interface")
	}

	for _, addr := range addrs {
		v, ok := (addr).(*net.IPNet)
		if !ok {
			continue
		}

		if v.IP.To4() == nil {
			continue
		}

		return v.IP, nil
	}

	return nil, errors.New("No IP found on interface")
}
