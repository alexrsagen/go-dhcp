package dhcpv4

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"time"

	"../internal/ifnet"
)

// Client is a DHCPv4 client
type Client struct {
	Interface       *net.Interface
	Server          net.IP
	Options         map[uint8]interface{}
	NoAutoClientID  bool
	NoAutoHostname  bool
	MaxWriteRetries uint8
	MaxReadRetries  uint8
	Timeout         time.Duration
}

func (c *Client) init() error {
	if c.Interface == nil {
		return errors.New("Interface not set")
	}

	if c.Server == nil {
		c.Server = net.IPv4bcast
	}

	if c.Options[OptionClientID] == nil && !c.NoAutoClientID {
		c.Options[OptionClientID] = []byte{HardwareTypeEthernet, 0, 0, 0, 0, 0, 0}
		copy(c.Options[OptionClientID].([]byte)[1:], c.Interface.HardwareAddr)
	}

	if c.Options[OptionHostname] == nil && !c.NoAutoHostname {
		hostname, _ := os.Hostname()
		c.Options[OptionHostname] = hostname
	}

	return nil
}

// Discover broadcasts a single DHCPDISCOVER request and returns DHCPOFFER replies
func (c *Client) Discover() ([]*Packet, error) {
	if err := c.init(); err != nil {
		return nil, fmt.Errorf("Client.init: %v", err)
	}

	xid, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	if err != nil {
		return nil, fmt.Errorf("rand.Int: %v", err)
	}

	p := &Packet{
		Operation:      OpRequest,
		HardwareType:   HardwareTypeEthernet,
		HardwareLength: uint8(len(c.Interface.HardwareAddr)),
		TransactionID:  uint32(xid.Uint64()),
		Flags:          flagBroadcast,
	}
	copy(p.ClientHardwareAddress[:], c.Interface.HardwareAddr)
	c.Options[OptionMessageType] = MessageTypeDiscover
	p.SetOptions(c.Options)

	srcIP, err := findSourceIPv4(c.Interface)
	if err != nil {
		return nil, fmt.Errorf("findSourceIPv4: %v", err)
	}

	fmt.Printf("[debug] Starting DHCP client on interface %s with IP %s\n", c.Interface.HardwareAddr.String(), srcIP)

	ln, err := ifnet.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: portClient,
	}, c.Interface)
	if err != nil {
		return nil, fmt.Errorf("ifnet.ListenUDP: %v", err)
	}

	bytes, err := p.toBytes()
	if err != nil {
		return nil, fmt.Errorf("packet.toBytes: %v", err)
	}

	var tries uint8

	fmt.Printf("[debug] Broadcasting %d bytes: %x\n", len(bytes), bytes)
	n, err := ln.WriteToUDP(bytes, &net.UDPAddr{
		IP:   c.Server,
		Port: portServer,
	})
	if err != nil {
		return nil, fmt.Errorf("ifnet.UDPConn.WriteToUDP: %v", err)
	}
	fmt.Printf("[debug] Broadcasted %d bytes\n", n)

	data := make([]byte, dhcpMaxPacketSize)
	responses := []*Packet{}

	for tries = 0; tries < 1+c.MaxReadRetries; tries++ {
		if tries > 0 {
			// clear buffer
			for i := 0; i < n; i++ {
				data[i] = 0
			}
		}

		// read packet
		n, src, err := ln.ReadFromUDP(data)
		if err != nil {
			return nil, fmt.Errorf("ifnet.UDPConn.ReadFromUDP: %v", err)
		}
		if n == 0 {
			fmt.Printf("[debug] Received empty packet from %s\n", src)
			continue
		}
		fmt.Printf("[debug] Received %d bytes from %s: %x\n", n, src, data[:n])

		// parse packet
		resp, err := parsePacket(data)
		if err != nil {
			return nil, fmt.Errorf("parsePacket: %v", err)
		}
		responses = append(responses, resp)
	}

	return responses, nil
}
