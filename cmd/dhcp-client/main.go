package main

import (
	"fmt"
	"net"

	"../../pkg/dhcp/dhcpv4"
)

func main() {
	i, err := net.InterfaceByIndex(15)
	if err != nil {
		panic(err)
	}

	c := &dhcpv4.Client{
		Interface:      i,
		NoAutoHostname: true,
		Options: map[uint8]interface{}{
			dhcpv4.OptionParameterList: []byte{
				dhcpv4.OptionSubnetMask,
				dhcpv4.OptionClasslessRoutes,
				dhcpv4.OptionRouters,
				dhcpv4.OptionStaticRoutes,
				dhcpv4.OptionDomainNameServers,
				dhcpv4.OptionRenewalTime,
				dhcpv4.OptionRebindingTime,
			},
		},
	}

	packets, err := c.Discover()
	if err != nil {
		panic(err)
	}

	for i, p := range packets {
		fmt.Printf("-- packet %d / %d --\n", i+1, len(packets))
		fmt.Printf("op = %d\n", p.Operation)
		fmt.Printf("htype = %d\n", p.HardwareType)
		fmt.Printf("hlen = %d\n", p.HardwareLength)
		fmt.Printf("nhops = %d\n", p.Hops)
		fmt.Printf("xid = %d\n", p.TransactionID)
		fmt.Printf("secs = %d\n", p.Seconds)
		fmt.Printf("flags = %d\n", p.Flags)
		fmt.Printf("ciaddr = %v\n", net.IP(p.ClientIP[:]))
		fmt.Printf("yiaddr = %v\n", net.IP(p.YourIP[:]))
		fmt.Printf("siaddr = %v\n", net.IP(p.ServerIP[:]))
		fmt.Printf("giaddr = %v\n", net.IP(p.GatewayIP[:]))
		fmt.Printf("chaddr = %v\n", net.HardwareAddr(p.ClientHardwareAddress[:]))
		fmt.Printf("sname = %s\n", string(p.ServerHostname[:]))
		fmt.Printf("file = %s\n", string(p.BootFilename[:]))
		fmt.Printf("options = %v\n", p.GetOptions())
	}
}
