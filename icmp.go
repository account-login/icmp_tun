package icmp_tun

// Internet Control Message Protocol (ICMP) Parameters, Updated: 2018-02-26
const (
	ICMPTypeEchoReply = 0 // Echo Reply
	//ICMPTypeDestinationUnreachable = 3  // Destination Unreachable
	//ICMPTypeRedirect               = 5  // Redirect
	ICMPTypeEcho = 8 // Echo
	//ICMPTypeRouterAdvertisement    = 9  // Router Advertisement
	//ICMPTypeRouterSolicitation     = 10 // Router Solicitation
	//ICMPTypeTimeExceeded           = 11 // Time Exceeded
	//ICMPTypeParameterProblem       = 12 // Parameter Problem
	//ICMPTypeTimestamp              = 13 // Timestamp
	//ICMPTypeTimestampReply         = 14 // Timestamp Reply
	//ICMPTypePhoturis               = 40 // Photuris
	//ICMPTypeExtendedEchoRequest    = 42 // Extended Echo Request
	//ICMPTypeExtendedEchoReply      = 43 // Extended Echo Reply
)

const ICMPEchoHeaderSize = 8
