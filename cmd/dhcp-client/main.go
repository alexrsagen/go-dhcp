package main

import (
	"net"

	"../../pkg/dhcp/dhcpv4"
)

func main() {
	i, err := net.InterfaceByIndex(5)
	if err != nil {
		panic(err)
	}
	c := &dhcpv4.Client{
		Interface: i,
		Options: map[uint8]interface{}{
			dhcpv4.OptionParameterList: []byte{
				dhcpv4.OptionSubnetMask,
				dhcpv4.OptionClasslessRoutes,
				dhcpv4.OptionRouters,
				dhcpv4.OptionStaticRoutes,
				dhcpv4.OptionDomainNameServers,
			},
		},
	}
	_, err = c.Discover()
	if err != nil {
		panic(err)
	}
}
