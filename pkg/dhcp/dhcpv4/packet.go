package dhcpv4

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"
)

// packet is an RFC2131 DHCP packet without the variable length options field
type packet struct {
	op, htype, hlen, hops          uint8
	xid                            uint32
	secs, flags                    uint16
	ciaddr, yiaddr, siaddr, giaddr [4]byte
	chaddr                         [16]byte
	sname                          [64]byte
	file                           [128]byte
}

const udpOverhead = (20 + // IP header size
	8) // UDP header size
const dhcpFixedNonUDP = unsafe.Sizeof(packet{})
const dhcpFixedLen = dhcpFixedNonUDP + udpOverhead
const dhcpOptionsLenMax = 1500 - dhcpFixedLen // 1500 = largest possible ethernet MTU according to RFC894
const dhcpOptionsLenMin = 576 - dhcpFixedLen  // 576 = smallest ethernet MTU that MUST be supported according to RFC791
const bootpOptionsLen = 64

// Packet is an RFC2131 DHCP packet
type Packet struct {
	Operation, HardwareType, HardwareLength, Hops uint8
	TransactionID                                 uint32
	Seconds, Flags                                uint16
	ClientIP, YourIP, ServerIP, GatewayIP         [4]byte
	ClientHardwareAddress                         [16]byte
	ServerHostname                                [64]byte
	BootFilename                                  [128]byte
	Options                                       [dhcpOptionsLenMax]byte
}

const dhcpMaxPacketSize = unsafe.Sizeof(Packet{})

// The Options type is a nice way of representing DHCP option codes
type Options map[uint8]interface{}

func (p *Packet) optionsLen() (end int) {
	for idx := 0; idx < cap(p.Options)-1; idx++ { // seek to next option
		code := p.Options[idx]
		if idx < len(dhcpCookie) && code == dhcpCookie[idx] { // skip magic cookie
			continue
		}
		if code == OptionPad { // skip padding
			continue
		}
		if code == OptionEnd { // end on first option code OptionEnd
			end = idx + 1 // update end index
			return
		}
		idx += 1 + int(p.Options[idx+1]) // increment idx by option length
		end = idx                        // update end index
	}
	return
}

// GetOptions parses the packet options field and returns it as an Options type
func (p *Packet) GetOptions() Options {
	opts := Options{}

	if len(p.Options) < len(dhcpCookie) {
		return opts
	}
	if bytes.Compare(p.Options[:len(dhcpCookie)], dhcpCookie[:len(dhcpCookie)]) != 0 {
		return opts
	}

	for idx := len(dhcpCookie); idx < p.optionsLen(); idx++ {
		code := p.Options[idx]
		if code == OptionEnd {
			break
		}
		idx++
		optlen := int(p.Options[idx])
		idx++
		opts[code] = p.Options[idx : idx+optlen]
		idx += optlen - 1
		// fmt.Printf("[debug] Read DHCP Option code %d, length %d, value %v\n", code, optlen, opts[code])
	}

	return opts
}

// SetOptions clears a packet options field and fills it with the provided values.
// Currently supports a wide variety of types for all RFC2132 options.
func (p *Packet) SetOptions(opts Options) error {
	// clear option buffer in case of packet reuse
	// or multiple calls to SetOptions
	for i := range p.Options {
		p.Options[i] = 0
	}

	// copy DHCP cookie to option buffer
	copy(p.Options[:4], dhcpCookie[:4])
	idx := 4

	for code, _val := range opts {
		p.Options[idx] = code
		idx++

		switch code {
		// uint32 / [1-4]uint32 / [(1+n*4)-32]byte / [1-4][4]byte
		case OptionRouters, OptionTimeServers, OptionNameServers,
			OptionDomainNameServers, OptionLogServers, OptionCookieServers,
			OptionLPRServers, OptionImpressServers, OptionResourceLocationServers:
			switch _val.(type) {
			case uint32: // uint32
				val := _val.(uint32)
				p.Options[idx] = 4
				idx++
				binary.BigEndian.PutUint32(p.Options[idx:idx+4], val)
				idx += 4
			case []uint32: // [1-4]uint32
				val := _val.([]uint32)
				if len(val) == 0 || len(val) > 4 {
					return errors.New("Invalid option value")
				}
				p.Options[idx] = uint8(len(val) * 4)
				idx++
				for i := range val {
					binary.BigEndian.PutUint32(p.Options[idx:idx+4], val[i])
					idx += 4
				}
			case [][4]byte: // [1-4][4]byte
				val := _val.([][4]byte)
				if len(val) == 0 || len(val) > 4 {
					return errors.New("Invalid option value")
				}
				p.Options[idx] = uint8(len(val) * 4)
				idx++
				for i := range val {
					copy(p.Options[idx:idx+4], val[i][:4])
					idx += 4
				}
			case []byte: // [(1+n*4)-32]byte
				val := _val.([]byte)
				if len(val) == 0 || len(val)%4 != 0 || len(val) > 32 {
					return errors.New("Invalid option value")
				}
				p.Options[idx] = uint8(len(val))
				idx++
				copy(p.Options[idx:idx+len(val)], val)
				idx += len(val)
			default:
				return errors.New("Invalid option type")
			}

		// Same type as above, except no maximum of 4 addresses
		// uint32 / [1+]uint32 / [1+n*4]byte / [1+][4]byte
		case OptionNISServers, OptionNTPServers, OptionNetBIOSNameServers,
			OptionNetBIOSDistServers, OptionFontServers, OptionXDisplayManager,
			OptionNISPlusServers, OptionSMTPServers, OptionPOPServers,
			OptionNNTPServers, OptionWWWServers, OptionFingerServers,
			OptionIRCServers, OptionStreetTalkServers, OptionSTDAServers:
			switch _val.(type) {
			case uint32: // uint32
				val := _val.(uint32)
				p.Options[idx] = 4
				idx++
				binary.BigEndian.PutUint32(p.Options[idx:idx+4], val)
				idx += 4
			case []uint32: // [1+]uint32
				val := _val.([]uint32)
				if len(val) == 0 {
					return errors.New("Invalid option value")
				}
				p.Options[idx] = uint8(len(val) * 4)
				idx++
				for i := range val {
					binary.BigEndian.PutUint32(p.Options[idx:idx+4], val[i])
					idx += 4
				}
			case [][4]byte: // [1+][4]byte
				val := _val.([][4]byte)
				if len(val) == 0 {
					return errors.New("Invalid option value")
				}
				p.Options[idx] = uint8(len(val) * 4)
				idx++
				for i := range val {
					copy(p.Options[idx:idx+4], val[i][:4])
					idx += 4
				}
			case []byte: // [1+n*4]byte
				val := _val.([]byte)
				if len(val) == 0 || len(val)%4 != 0 {
					return errors.New("Invalid option value")
				}
				p.Options[idx] = uint8(len(val))
				idx++
				copy(p.Options[idx:idx+len(val)], val)
				idx += len(val)
			default:
				return errors.New("Invalid option type")
			}

		// Same type as above, except no minimum of 1 address
		// uint32 / []uint32 / [n*4]byte / [][4]byte
		case OptionHomeAgentAddrs:
			switch _val.(type) {
			case uint32: // uint32
				val := _val.(uint32)
				if val == 0 {
					continue
				}
				p.Options[idx] = 4
				idx++
				binary.BigEndian.PutUint32(p.Options[idx:idx+4], val)
				idx += 4
			case []uint32: // []uint32
				val := _val.([]uint32)
				if len(val) == 0 {
					continue
				}
				p.Options[idx] = uint8(len(val) * 4)
				idx++
				for i := range val {
					binary.BigEndian.PutUint32(p.Options[idx:idx+4], val[i])
					idx += 4
				}
			case [][4]byte: // [][4]byte
				val := _val.([][4]byte)
				if len(val) == 0 {
					continue
				}
				p.Options[idx] = uint8(len(val) * 4)
				idx++
				for i := range val {
					copy(p.Options[idx:idx+4], val[i][:4])
					idx += 4
				}
			case []byte: // [n*4]byte
				val := _val.([]byte)
				if len(val) == 0 {
					continue
				}
				if len(val)%4 != 0 {
					return errors.New("Invalid option value")
				}
				p.Options[idx] = uint8(len(val))
				idx++
				copy(p.Options[idx:idx+len(val)], val)
				idx += len(val)
			default:
				return errors.New("Invalid option type")
			}

		// [2]uint32 / [1-4][2]uint32 / [(n*8)-64]byte / [1-4][2][4]byte
		case OptionPolicyFilters, OptionStaticRoutes:
			switch _val.(type) {
			case [2]uint32: // [2]uint32
				val := _val.([2]uint32)
				p.Options[idx] = 8
				idx++
				binary.BigEndian.PutUint32(p.Options[idx:idx+4], val[0])
				idx += 4
				binary.BigEndian.PutUint32(p.Options[idx:idx+4], val[1])
				idx += 4
			case [][2]uint32: // [1-4][2]uint32
				val := _val.([][2]uint32)
				if len(val) == 0 || len(val) > 4 {
					return errors.New("Invalid option value")
				}
				p.Options[idx] = uint8(len(val) * 8)
				idx++
				for i := 0; i < len(val); i++ {
					binary.BigEndian.PutUint32(p.Options[idx:idx+4], val[i][0])
					idx += 4
					binary.BigEndian.PutUint32(p.Options[idx:idx+4], val[i][1])
					idx += 4
				}
			case [][2][4]byte: // [1-4][2][4]byte
				val := _val.([][2][4]byte)
				if len(val) == 0 || len(val) > 4 {
					return errors.New("Invalid option value")
				}
				p.Options[idx] = uint8(len(val) * 2 * 4)
				idx++
				for i := 0; i < len(val); i++ {
					copy(p.Options[idx:idx+4], val[i][0][:4])
					idx += 4
					copy(p.Options[idx:idx+4], val[i][1][:4])
					idx += 4
				}
			case []byte: // [(n*8)-64]byte
				val := _val.([]byte)
				if len(val) == 0 || len(val)%8 != 0 || len(val) > 64 {
					return errors.New("Invalid option value")
				}
				p.Options[idx] = uint8(len(val))
				idx++
				copy(p.Options[idx:idx+len(val)], val)
				idx += len(val)
			default:
				return errors.New("Invalid option type")
			}

		// uint32 / [4]byte
		case OptionSubnetMask, OptionTimeOffset, OptionSwapServer,
			OptionMTUAgingTimeout, OptionBroadcastAddr, OptionRouterSolicitationAddr,
			OptionARPCacheTimeout, OptionTCPKeepaliveInterval, OptionRequestedIPAddr,
			OptionIPAddrLeaseTime, OptionServerID, OptionRenewalTime,
			OptionRebindingTime:
			p.Options[idx] = 4
			idx++
			switch _val.(type) {
			case uint32:
				val := _val.(uint32)
				binary.BigEndian.PutUint32(p.Options[idx:idx+4], val)
			case [4]byte:
				val := _val.([4]byte)
				copy(p.Options[idx:idx+4], val[:4])
			default:
				return errors.New("Invalid option type")
			}
			idx += 4

		// uint16 / [1+]uint16 / [2]byte / [1+][2]byte
		case OptionMTUPlateauTable:
			switch _val.(type) {
			case uint16:
				val := _val.(uint16)
				if val < 68 {
					return errors.New("Invalid option value")
				}
				p.Options[idx] = 2
				idx++
				binary.BigEndian.PutUint16(p.Options[idx:idx+2], val)
				idx += 2
			case []uint16:
				val := _val.([]uint16)
				if len(val) == 0 {
					return errors.New("Invalid option value")
				}
				p.Options[idx] = uint8(len(val) * 2)
				idx++
				for i := range val {
					if val[i] < 68 {
						return errors.New("Invalid option value")
					}
					binary.BigEndian.PutUint16(p.Options[idx:idx+2], val[i])
					idx += 2
				}
			case [][2]byte:
				val := _val.([][2]byte)
				if len(val) == 0 {
					return errors.New("Invalid option value")
				}
				p.Options[idx] = uint8(len(val) * 2)
				idx++
				for i := range val {
					if binary.BigEndian.Uint16(val[i][:2]) < 68 {
						return errors.New("Invalid option value")
					}
					copy(p.Options[idx:idx+2], val[i][:2])
					idx += 2
				}
			case [2]byte:
				val := _val.([2]byte)
				if binary.BigEndian.Uint16(val[:2]) < 68 {
					return errors.New("Invalid option value")
				}
				p.Options[idx] = 2
				idx++
				copy(p.Options[idx:idx+2], val[:2])
				idx += 2
			default:
				return errors.New("Invalid option type")
			}

		// uint16 / [2]byte
		case OptionBootFileSize, OptionMaxDatagramAssembly, OptionInterfaceMTU,
			OptionMaxMessageSize:
			p.Options[idx] = 2
			idx++
			switch _val.(type) {
			case uint16:
				val := _val.(uint16)
				binary.BigEndian.PutUint16(p.Options[idx:idx+2], val)
			case [2]byte:
				val := _val.([2]byte)
				copy(p.Options[idx:idx+2], val[:2])
			default:
				return errors.New("Invalid option type")
			}
			idx += 2

		// uint8 / byte
		case OptionMessageType, OptionOverload, OptionDefaultIPTTL,
			OptionTCPDefaultTTL, OptionNetBIOSNodeType:
			p.Options[idx] = 1
			idx++
			switch _val.(type) {
			case uint8:
				val := _val.(uint8)
				if code == OptionOverload && (val == 0 || val > 3) {
					return errors.New("Invalid option value")
				}
				p.Options[idx] = val
			default:
				return errors.New("Invalid option type")
			}
			idx++

		// (uint8 / byte - 0/1) / bool
		case OptionIPForwardingEnable, OptionSourceRoutingEnable, OptionAllSubnetsAreLocal,
			OptionMaskDiscoveryEnable, OptionMaskSupplier, OptionRouterDiscoveryEnable,
			OptionTrailerEncapsulation, OptionEthernetEncapsulation, OptionTCPKeepaliveGarbage:
			p.Options[idx] = 1
			idx++
			switch _val.(type) {
			case uint8:
				val := _val.(uint8)
				if val > 1 {
					return errors.New("Invalid option value")
				}
				p.Options[idx] = val
			case bool:
				val := _val.(bool)
				if val {
					p.Options[idx] = 1
				} else {
					p.Options[idx] = 0
				}
			default:
				return errors.New("Invalid option type")
			}
			idx++

		// []uint8 / []byte
		case OptionParameterList:
			switch _val.(type) {
			case []byte:
				val := _val.([]byte)
				p.Options[idx] = uint8(len(val))
				idx++
				if code == OptionClientID && len(val) < 2 {
					return errors.New("Invalid option value")
				}
				copy(p.Options[idx:idx+len(val)], val)
				idx += len(val)
			default:
				return errors.New("Invalid option type")
			}

		// string / []byte
		case OptionMeritDumpFile, OptionDomainName, OptionRootPath,
			OptionExtensionsPath, OptionMessage, OptionNISDomain,
			OptionNetBIOSScope, OptionNISPlusDomainName, OptionTFTPServerName,
			OptionBootFileName, OptionHostname:
			switch _val.(type) {
			case string:
				val := _val.(string)
				p.Options[idx] = uint8(len(val))
				idx++
				copy(p.Options[idx:idx+len(val)], []byte(val))
				idx += len(val)
			case []byte:
				val := _val.([]byte)
				p.Options[idx] = uint8(len(val))
				idx++
				copy(p.Options[idx:idx+len(val)], val)
				idx += len(val)
			default:
				return errors.New("Invalid option type")
			}

		// []byte
		case OptionClassID, OptionClientID, OptionVendorSpecificOptions:
			fallthrough
		default:
			switch _val.(type) {
			case []byte:
				val := _val.([]byte)
				if len(val) == 0 {
					return errors.New("Invalid option value")
				}
				if code == OptionClientID && len(val) < 2 {
					return errors.New("Invalid option value")
				}

				p.Options[idx] = uint8(len(val))
				idx++
				copy(p.Options[idx:idx+len(val)], val)
				idx += len(val)
			default:
				return errors.New("Invalid option type")
			}
		}
	}

	p.Options[idx] = OptionEnd

	return nil
}

func (p *Packet) toBytes() ([]byte, error) {
	// convert struct data to byte slice
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.BigEndian, p)
	if err != nil {
		return nil, fmt.Errorf("binary.Write: %v", err)
	}
	bytes := buf.Bytes()

	// resize byte slice to be as small as possible
	// but still no smaller than minimum BOOTP packet size
	optionsLen := p.optionsLen()
	if optionsLen < bootpOptionsLen {
		bytes = bytes[:dhcpFixedNonUDP+bootpOptionsLen]
	} else {
		bytes = bytes[:int(dhcpFixedNonUDP)+optionsLen]
	}

	return bytes, nil
}

func parsePacket(data []byte) (*Packet, error) {
	p := &Packet{}
	rd := bytes.NewReader(data)
	err := binary.Read(rd, binary.BigEndian, p)
	if err != nil {
		return nil, fmt.Errorf("binary.Read: %v", err)
	}
	return p, nil
}
