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

// from https://github.com/golang/net/blob/master/icmp/message.go
func checksum(b []byte) uint16 {
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
}

func checksumPut(dst []byte, src []byte) {
	dst[0] = 0
	dst[1] = 0
	s := checksum(src)
	dst[0] = byte(s)
	dst[1] = byte(s >> 8)
}

func checksumUpdate(dst []byte, old uint16, new uint16) {
	s := uint32(dst[0]) + uint32(dst[1])<<8
	s += uint32(old) + uint32(^new)
	s = s>>16 + s&0xffff
	s = s + s>>16
	dst[0] = byte(s)
	dst[1] = byte(s >> 8)
}
