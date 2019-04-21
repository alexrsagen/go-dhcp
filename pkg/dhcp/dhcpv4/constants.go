package dhcpv4

const portServer = 67
const portClient = 68

var dhcpCookie = [...]byte{0x63, 0x82, 0x53, 0x63}

const flagBroadcast = 0x8000

// States
type dhcpState uint8

const (
	stateInit dhcpState = iota
	stateInitReboot
	stateRebooting
	stateSelecting
	stateRequesting
	stateBound
	stateRenewing
	stateRebinding
)

// BOOTP Message Types
const (
	OpRequest uint8 = 1
	OpReply   uint8 = 2
)

// DHCP Message Type 53 Values
// https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml#message-type-53
// Last Updated: 2018-03-09
const (
	MessageTypeDiscover uint8 = 1 // [RFC2132]
	MessageTypeOffer    uint8 = 2 // [RFC2132]
	MessageTypeRequest  uint8 = 3 // [RFC2132]
	MessageTypeDecline  uint8 = 4 // [RFC2132]
	MessageTypeAck      uint8 = 5 // [RFC2132]
	MessageTypeNak      uint8 = 6 // [RFC2132]
	MessageTypeRelease  uint8 = 7 // [RFC2132]
	MessageTypeInform   uint8 = 8 // [RFC2132]

	// DHCP reconfigure extension
	MessageTypeForceRenew uint8 = 9 // [RFC3203]

	// Dynamic Host Configuration Protocol (DHCP) Leasequery
	MessageTypeLeaseQuery      uint8 = 10 // [RFC4388]
	MessageTypeLeaseUnassigned uint8 = 11 // [RFC4388]
	MessageTypeLeaseUnknown    uint8 = 12 // [RFC4388]
	MessageTypeLeaseActive     uint8 = 13 // [RFC4388]

	// DHCPv4 Bulk Leasequery
	MessageTypeBulkLeaseQuery uint8 = 14 // [RFC6926]
	MessageTypeLeaseQueryDone uint8 = 15 // [RFC6926]

	// Active DHCPv4 Lease Query
	MessageTypeActiveLeaseQuery uint8 = 16 // [RFC7724]
	MessageTypeLeaseQueryStatus uint8 = 17 // [RFC7724]
	MessageTypeTLS              uint8 = 18 // [RFC7724]
)

// DHCP State Type 156 Values
// https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml#type-156
// Last Updated: 2018-03-09
const (
	// DHCPv4 Bulk Leasequery
	LeaseQueryStateReserved      uint8 = 0 // [RFC6926]
	LeaseQueryStateAvailable     uint8 = 1 // [RFC6926]
	LeaseQueryStateActive        uint8 = 2 // [RFC6926]
	LeaseQueryStateExpired       uint8 = 3 // [RFC6926]
	LeaseQueryStateReleased      uint8 = 4 // [RFC6926]
	LeaseQueryStateAbandoned     uint8 = 5 // [RFC6926]
	LeaseQueryStateReset         uint8 = 6 // [RFC6926]
	LeaseQueryStateRemote        uint8 = 7 // [RFC6926]
	LeaseQueryStateTransitioning uint8 = 8 // [RFC6926]
)

// Hardware Types
// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
// 2016-07-20
const (
	HardwareTypeEthernet   uint8 = 1   // [Jon Postel] Ethernet 10Mbps
	HardwareTypeTokenRing  uint8 = 6   // [Jon Postel] IEEE 802.2 Token Ring
	HardwareTypeFDDI       uint8 = 8   // [Jon Postel] FDDI / Hyperchannel
	HardwareTypeInfiniband uint8 = 32  // [RFC4391] IP over Infiniband
	HardwareTypeIPMP       uint8 = 255 // [ISC] IPMP - random hw address - there is no standard for this so we just steal a type
)

// BOOTP Vendor Extensions and DHCP Options
// https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml#options
// Last Updated: 2018-03-09
const (
	// DHCP options
	OptionEnd                     uint8 = 255 // [RFC2132] End
	OptionPad                     uint8 = 0   // [RFC2132] Pad
	OptionSubnetMask              uint8 = 1   // [RFC2132] Subnet Mask Value
	OptionTimeOffset              uint8 = 2   // [RFC2132] Time Offset in Seconds from UTC (note: deprecated by 100 and 101)
	OptionRouters                 uint8 = 3   // [RFC2132] N/4 Router Addresses
	OptionTimeServers             uint8 = 4   // [RFC2132] N/4 Timeserver Addresses
	OptionNameServers             uint8 = 5   // [RFC2132] N/4 IEN-116 Server Addresses
	OptionDomainNameServers       uint8 = 6   // [RFC2132] N/4 DNS Server Addresses
	OptionLogServers              uint8 = 7   // [RFC2132] N/4 Logging Server Addresses
	OptionCookieServers           uint8 = 8   // [RFC2132] N/4 Quotes Server Addresses (RFC865)
	OptionLPRServers              uint8 = 9   // [RFC2132] N/4 Printer Server Addresses
	OptionImpressServers          uint8 = 10  // [RFC2132] N/4 Impress Server Addresses
	OptionResourceLocationServers uint8 = 11  // [RFC2132] N/4 RLP Server Addresses
	OptionHostname                uint8 = 12  // [RFC2132] Hostname string
	OptionBootFileSize            uint8 = 13  // [RFC2132] Size of boot file in 512 byte chunks
	OptionMeritDumpFile           uint8 = 14  // [RFC2132] Client to dump and name the file to dump it to
	OptionDomainName              uint8 = 15  // [RFC2132] The DNS domain name of the client
	OptionSwapServer              uint8 = 16  // [RFC2132] Swap Server address
	OptionRootPath                uint8 = 17  // [RFC2132] Path name for root disk
	OptionExtensionsPath          uint8 = 18  // [RFC2132] Path name for more BOOTP info

	// DHCP extensions
	OptionVendorSpecificOptions uint8 = 43  // [RFC2132] Vendor Specific Information
	OptionRequestedIPAddr       uint8 = 50  // [RFC2132] Requested IP Address
	OptionIPAddrLeaseTime       uint8 = 51  // [RFC2132] IP Address Lease Time
	OptionOverload              uint8 = 52  // [RFC2132] Overload "sname" or "file"
	OptionMessageType           uint8 = 53  // [RFC2132] DHCP Message Type
	OptionServerID              uint8 = 54  // [RFC2132] DHCP Server Identification
	OptionParameterList         uint8 = 55  // [RFC2132] Parameter Request List
	OptionMessage               uint8 = 56  // [RFC2132] DHCP Error Message
	OptionMaxMessageSize        uint8 = 57  // [RFC2132] DHCP Maximum Message Size
	OptionRenewalTime           uint8 = 58  // [RFC2132] DHCP Renewal (T1) Time
	OptionRebindingTime         uint8 = 59  // [RFC2132] DHCP Rebinding (T2) Time
	OptionClassID               uint8 = 60  // [RFC2132] Class Identifier
	OptionClientID              uint8 = 61  // [RFC2132] Client Identifier
	OptionUserClass             uint8 = 77  // [RFC3004] User Class Information
	OptionFQDN                  uint8 = 81  // [RFC4702] Client FQDN
	OptionRelayAgentOptions     uint8 = 82  // [RFC3046] DHCP Relay Agent Information Option
	OptionAuthentication        uint8 = 90  // [RFC3118] Authentication for DHCP Messages
	OptionSubnetSelection       uint8 = 118 // [RFC3011] Subnet Selection Option
	OptionDomainSearch          uint8 = 119 // [RFC3397] DNS domain search list
	OptionClasslessRoutes       uint8 = 121 // [RFC3442] Classless Static Route Option

	// Dynamic Host Configuration Protocol (DHCP) Leasequery
	OptionClientLastTransactionTime uint8 = 91 // [RFC4388] An integer number of seconds in the past from the time the DHCPLEASEACTIVE message is sent that the client last dealt with this server about this IP address
	OptionAssociatedIP              uint8 = 92 // [RFC4388] All of the IP addresses associated with the DHCP client specified in a particular DHCPLEASEQUERY message

	// Timezone Options for DHCP
	OptionPCode uint8 = 100 // [RFC4833] IEEE 1003.1 TZ String
	OptionTCode uint8 = 101 // [RFC4833] Reference to the TZ Database

	// Layer 3 parameters
	OptionIPForwardingEnable  uint8 = 19 // [RFC2132] Enable/Disable IP Forwarding
	OptionSourceRoutingEnable uint8 = 20 // [RFC2132] Enable/Disable Source Routing
	OptionPolicyFilters       uint8 = 21 // [RFC2132] Routing Policy Filters
	OptionMaxDatagramAssembly uint8 = 22 // [RFC2132] Max Datagram Reassembly Size
	OptionDefaultIPTTL        uint8 = 23 // [RFC2132] Default IP Time to Live
	OptionMTUAgingTimeout     uint8 = 24 // [RFC2132] Path MTU Aging Timeout
	OptionMTUPlateauTable     uint8 = 25 // [RFC2132] Path MTU Plateau Table

	// Layer 3 parameters (per-interface)
	OptionInterfaceMTU           uint8 = 26 // [RFC2132] Interface MTU Size (Layer 3 / IP MTU)
	OptionAllSubnetsAreLocal     uint8 = 27 // [RFC2132] All Subnets are Local
	OptionBroadcastAddr          uint8 = 28 // [RFC2132] Broadcast Address
	OptionMaskDiscoveryEnable    uint8 = 29 // [RFC2132] Perform Mask Discovery
	OptionMaskSupplier           uint8 = 30 // [RFC2132] Provide Mask to Others
	OptionRouterDiscoveryEnable  uint8 = 31 // [RFC2132] Perform Router Discovery
	OptionRouterSolicitationAddr uint8 = 32 // [RFC2132] Router Solicitation Address
	OptionStaticRoutes           uint8 = 33 // [RFC2132] Static Routing Table

	// Layer 2 parameters (per-interface)
	OptionTrailerEncapsulation  uint8 = 34 // [RFC2132] Trailer Encapsulation
	OptionARPCacheTimeout       uint8 = 35 // [RFC2132] ARP Cache Timeout
	OptionEthernetEncapsulation uint8 = 36 // [RFC2132] Ethernet Encapsulation

	// Layer 4 TCP parameters
	OptionTCPDefaultTTL        uint8 = 37 // [RFC2132] Default TCP Time to Live
	OptionTCPKeepaliveInterval uint8 = 38 // [RFC2132] TCP Keepalive Interval
	OptionTCPKeepaliveGarbage  uint8 = 39 // [RFC2132] TCP Keepalive Garbage

	// Layer 7 parameters
	OptionNISDomain          uint8 = 40  // [RFC2132] NIS Domain Name
	OptionNISServers         uint8 = 41  // [RFC2132] NIS Server Addresses
	OptionNTPServers         uint8 = 42  // [RFC2132] NTP Server Addresses
	OptionNetBIOSNameServers uint8 = 44  // [RFC2132] NETBIOS Name Servers
	OptionNetBIOSDistServers uint8 = 45  // [RFC2132] NETBIOS Datagram Distribution Servers
	OptionNetBIOSNodeType    uint8 = 46  // [RFC2132] NETBIOS Node Type
	OptionNetBIOSScope       uint8 = 47  // [RFC2132] NETBIOS Scope
	OptionFontServers        uint8 = 48  // [RFC2132] X Window Font Servers
	OptionXDisplayManager    uint8 = 49  // [RFC2132] X Window Display Manager
	OptionNISPlusDomainName  uint8 = 64  // [RFC2132] NIS+ v3 Client Domain Name
	OptionNISPlusServers     uint8 = 65  // [RFC2132] NIS+ v3 Server Addresses
	OptionTFTPServerName     uint8 = 66  // [RFC2132] TFTP Server Name
	OptionBootFileName       uint8 = 67  // [RFC2132] Boot File Name
	OptionHomeAgentAddrs     uint8 = 68  // [RFC2132] Home Agent Addresses
	OptionSMTPServers        uint8 = 69  // [RFC2132] Simple Mail Server Addresses
	OptionPOPServers         uint8 = 70  // [RFC2132] Post Office Server Addresses
	OptionNNTPServers        uint8 = 71  // [RFC2132] Network News Server Addresses
	OptionWWWServers         uint8 = 72  // [RFC2132] WWW Server Addresses
	OptionFingerServers      uint8 = 73  // [RFC2132] Finger Server Addresses
	OptionIRCServers         uint8 = 74  // [RFC2132] Chat Server Addresses
	OptionStreetTalkServers  uint8 = 75  // [RFC2132] StreetTalk Server Addresses
	OptionSTDAServers        uint8 = 76  // [RFC2132] ST Directory Assist. Addresses
	OptionCAPWAPControllers  uint8 = 138 // [RFC5417] CAPWAP Access Controller Addresses
)
