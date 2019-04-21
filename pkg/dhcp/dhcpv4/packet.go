package dhcpv4

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unsafe"
)

// BOOTP/DHCPv4 base packet structure
type packet struct {
	op, htype, hlen, hops          uint8
	xid                            uint32
	secs, flags                    uint16
	ciaddr, yiaddr, siaddr, giaddr uint32
	chaddr                         [16]byte
	sname                          [64]byte
	file                           [128]byte
}

const udpOverhead = (20 + // IP header size
	8) // UDP header size
const dhcpFixedNonUDP = unsafe.Sizeof(*new(packet))
const dhcpFixedLen = dhcpFixedNonUDP + udpOverhead
const dhcpOptionsLenMax = 1500 - dhcpFixedLen // 1500 = largest possible ethernet MTU according to RFC894
const dhcpOptionsLenMin = 576 - dhcpFixedLen  // 576 = smallest ethernet MTU that MUST be supported according to RFC791
const bootpOptionsLen = 64

// Packet holds data in the RFC2132 packet format
type Packet struct {
	op, htype, hlen, hops          uint8
	xid                            uint32
	secs, flags                    uint16
	ciaddr, yiaddr, siaddr, giaddr uint32
	chaddr                         [16]byte
	sname                          [64]byte
	file                           [128]byte
	options                        [dhcpOptionsLenMax]byte
}

const dhcpMaxPacketSize = unsafe.Sizeof(*new(Packet))

// The Options type is a nice way of representing DHCP option codes
type Options map[uint8]interface{}

func (p *Packet) optionsLen() (end int) {
	for idx := 0; idx < cap(p.options)-1; idx++ { // seek to next option
		code := p.options[idx]
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
		idx += 1 + int(p.options[idx+1]) // increment idx by option length
		end = idx                        // update end index
	}
	return
}

// GetOptions parses the packet options field and returns it as an Options type
func (p *Packet) GetOptions() Options {
	if len(p.options) < 4 {
		return nil
	}
	if bytes.Compare(p.options[:4], dhcpCookie[:4]) != 0 {
		return nil
	}

	opts := Options{}

	for idx := 4; idx < len(p.options); idx++ {
		code := p.options[idx]
		idx++
		len := int(p.options[idx])
		idx++
		opts[code] = p.options[idx : idx+len]
		idx += len
	}

	return opts
}

// SetOptions clears a packet options field and fills it with the provided values.
// Currently supports a wide variety of types for all RFC2132 options.
func (p *Packet) SetOptions(opts Options) error {
	// clear option buffer in case of packet reuse
	// or multiple calls to SetOptions
	for i := range p.options {
		p.options[i] = 0
	}

	// copy DHCP cookie to option buffer
	copy(p.options[:4], dhcpCookie[:4])
	idx := 4

	for code, _val := range opts {
		p.options[idx] = code
		idx++

		switch code {
		// uint32 / [1-4]uint32 / [(1+n*4)-32]byte / [1-4][4]byte
		case OptionRouters, OptionTimeServers, OptionNameServers,
			OptionDomainNameServers, OptionLogServers, OptionCookieServers,
			OptionLPRServers, OptionImpressServers, OptionResourceLocationServers:
			switch _val.(type) {
			case uint32: // uint32
				val := _val.(uint32)
				p.options[idx] = 4
				idx++
				binary.BigEndian.PutUint32(p.options[idx:idx+4], val)
				idx += 4
			case []uint32: // [1-4]uint32
				val := _val.([]uint32)
				if len(val) == 0 || len(val) > 4 {
					return errors.New("Invalid option value")
				}
				p.options[idx] = uint8(len(val) * 4)
				idx++
				for i := range val {
					binary.BigEndian.PutUint32(p.options[idx:idx+4], val[i])
					idx += 4
				}
			case [][4]byte: // [1-4][4]byte
				val := _val.([][4]byte)
				if len(val) == 0 || len(val) > 4 {
					return errors.New("Invalid option value")
				}
				p.options[idx] = uint8(len(val) * 4)
				idx++
				for i := range val {
					copy(p.options[idx:idx+4], val[i][:4])
					idx += 4
				}
			case []byte: // [(1+n*4)-32]byte
				val := _val.([]byte)
				if len(val) == 0 || len(val)%4 != 0 || len(val) > 32 {
					return errors.New("Invalid option value")
				}
				p.options[idx] = uint8(len(val))
				idx++
				copy(p.options[idx:idx+len(val)], val)
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
				p.options[idx] = 4
				idx++
				binary.BigEndian.PutUint32(p.options[idx:idx+4], val)
				idx += 4
			case []uint32: // [1+]uint32
				val := _val.([]uint32)
				if len(val) == 0 {
					return errors.New("Invalid option value")
				}
				p.options[idx] = uint8(len(val) * 4)
				idx++
				for i := range val {
					binary.BigEndian.PutUint32(p.options[idx:idx+4], val[i])
					idx += 4
				}
			case [][4]byte: // [1+][4]byte
				val := _val.([][4]byte)
				if len(val) == 0 {
					return errors.New("Invalid option value")
				}
				p.options[idx] = uint8(len(val) * 4)
				idx++
				for i := range val {
					copy(p.options[idx:idx+4], val[i][:4])
					idx += 4
				}
			case []byte: // [1+n*4]byte
				val := _val.([]byte)
				if len(val) == 0 || len(val)%4 != 0 {
					return errors.New("Invalid option value")
				}
				p.options[idx] = uint8(len(val))
				idx++
				copy(p.options[idx:idx+len(val)], val)
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
				p.options[idx] = 4
				idx++
				binary.BigEndian.PutUint32(p.options[idx:idx+4], val)
				idx += 4
			case []uint32: // []uint32
				val := _val.([]uint32)
				if len(val) == 0 {
					continue
				}
				p.options[idx] = uint8(len(val) * 4)
				idx++
				for i := range val {
					binary.BigEndian.PutUint32(p.options[idx:idx+4], val[i])
					idx += 4
				}
			case [][4]byte: // [][4]byte
				val := _val.([][4]byte)
				if len(val) == 0 {
					continue
				}
				p.options[idx] = uint8(len(val) * 4)
				idx++
				for i := range val {
					copy(p.options[idx:idx+4], val[i][:4])
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
				p.options[idx] = uint8(len(val))
				idx++
				copy(p.options[idx:idx+len(val)], val)
				idx += len(val)
			default:
				return errors.New("Invalid option type")
			}

		// [2]uint32 / [1-4][2]uint32 / [(n*8)-64]byte / [1-4][2][4]byte
		case OptionPolicyFilters, OptionStaticRoutes:
			switch _val.(type) {
			case [2]uint32: // [2]uint32
				val := _val.([2]uint32)
				p.options[idx] = 8
				idx++
				binary.BigEndian.PutUint32(p.options[idx:idx+4], val[0])
				idx += 4
				binary.BigEndian.PutUint32(p.options[idx:idx+4], val[1])
				idx += 4
			case [][2]uint32: // [1-4][2]uint32
				val := _val.([][2]uint32)
				if len(val) == 0 || len(val) > 4 {
					return errors.New("Invalid option value")
				}
				p.options[idx] = uint8(len(val) * 8)
				idx++
				for i := 0; i < len(val); i++ {
					binary.BigEndian.PutUint32(p.options[idx:idx+4], val[i][0])
					idx += 4
					binary.BigEndian.PutUint32(p.options[idx:idx+4], val[i][1])
					idx += 4
				}
			case [][2][4]byte: // [1-4][2][4]byte
				val := _val.([][2][4]byte)
				if len(val) == 0 || len(val) > 4 {
					return errors.New("Invalid option value")
				}
				p.options[idx] = uint8(len(val) * 2 * 4)
				idx++
				for i := 0; i < len(val); i++ {
					copy(p.options[idx:idx+4], val[i][0][:4])
					idx += 4
					copy(p.options[idx:idx+4], val[i][1][:4])
					idx += 4
				}
			case []byte: // [(n*8)-64]byte
				val := _val.([]byte)
				if len(val) == 0 || len(val)%8 != 0 || len(val) > 64 {
					return errors.New("Invalid option value")
				}
				p.options[idx] = uint8(len(val))
				idx++
				copy(p.options[idx:idx+len(val)], val)
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
			p.options[idx] = 4
			idx++
			switch _val.(type) {
			case uint32:
				val := _val.(uint32)
				binary.BigEndian.PutUint32(p.options[idx:idx+4], val)
			case [4]byte:
				val := _val.([4]byte)
				copy(p.options[idx:idx+4], val[:4])
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
				p.options[idx] = 2
				idx++
				binary.BigEndian.PutUint16(p.options[idx:idx+2], val)
				idx += 2
			case []uint16:
				val := _val.([]uint16)
				if len(val) == 0 {
					return errors.New("Invalid option value")
				}
				p.options[idx] = uint8(len(val) * 2)
				idx++
				for i := range val {
					if val[i] < 68 {
						return errors.New("Invalid option value")
					}
					binary.BigEndian.PutUint16(p.options[idx:idx+2], val[i])
					idx += 2
				}
			case [][2]byte:
				val := _val.([][2]byte)
				if len(val) == 0 {
					return errors.New("Invalid option value")
				}
				p.options[idx] = uint8(len(val) * 2)
				idx++
				for i := range val {
					if binary.BigEndian.Uint16(val[i][:2]) < 68 {
						return errors.New("Invalid option value")
					}
					copy(p.options[idx:idx+2], val[i][:2])
					idx += 2
				}
			case [2]byte:
				val := _val.([2]byte)
				if binary.BigEndian.Uint16(val[:2]) < 68 {
					return errors.New("Invalid option value")
				}
				p.options[idx] = 2
				idx++
				copy(p.options[idx:idx+2], val[:2])
				idx += 2
			default:
				return errors.New("Invalid option type")
			}

		// uint16 / [2]byte
		case OptionBootFileSize, OptionMaxDatagramAssembly, OptionInterfaceMTU,
			OptionMaxMessageSize:
			p.options[idx] = 2
			idx++
			switch _val.(type) {
			case uint16:
				val := _val.(uint16)
				binary.BigEndian.PutUint16(p.options[idx:idx+2], val)
			case [2]byte:
				val := _val.([2]byte)
				copy(p.options[idx:idx+2], val[:2])
			default:
				return errors.New("Invalid option type")
			}
			idx += 2

		// uint8 / byte
		case OptionMessageType, OptionOverload, OptionDefaultIPTTL,
			OptionTCPDefaultTTL, OptionNetBIOSNodeType:
			p.options[idx] = 1
			idx++
			switch _val.(type) {
			case uint8:
				val := _val.(uint8)
				if code == OptionOverload && (val == 0 || val > 3) {
					return errors.New("Invalid option value")
				}
				p.options[idx] = val
			default:
				return errors.New("Invalid option type")
			}
			idx++

		// (uint8 / byte - 0/1) / bool
		case OptionIPForwardingEnable, OptionSourceRoutingEnable, OptionAllSubnetsAreLocal,
			OptionMaskDiscoveryEnable, OptionMaskSupplier, OptionRouterDiscoveryEnable,
			OptionTrailerEncapsulation, OptionEthernetEncapsulation, OptionTCPKeepaliveGarbage:
			p.options[idx] = 1
			idx++
			switch _val.(type) {
			case uint8:
				val := _val.(uint8)
				if val > 1 {
					return errors.New("Invalid option value")
				}
				p.options[idx] = val
			case bool:
				val := _val.(bool)
				if val {
					p.options[idx] = 1
				} else {
					p.options[idx] = 0
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
				p.options[idx] = uint8(len(val))
				idx++
				if code == OptionClientID && len(val) < 2 {
					return errors.New("Invalid option value")
				}
				copy(p.options[idx:idx+len(val)], val)
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
				p.options[idx] = uint8(len(val))
				idx++
				copy(p.options[idx:idx+len(val)], []byte(val))
				idx += len(val)
			case []byte:
				val := _val.([]byte)
				p.options[idx] = uint8(len(val))
				idx++
				copy(p.options[idx:idx+len(val)], val)
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

				p.options[idx] = uint8(len(val))
				idx++
				copy(p.options[idx:idx+len(val)], val)
				idx += len(val)
			default:
				return errors.New("Invalid option type")
			}
		}
	}

	p.options[idx] = OptionEnd

	return nil
}

func (p *Packet) toBytes() ([]byte, error) {
	// convert struct data to byte slice
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, p)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	return p, nil
}
