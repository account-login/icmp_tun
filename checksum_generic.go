package icmp_tun

// from https://github.com/golang/net/blob/master/icmp/message.go
func checksumGeneric(b []byte) uint16 {
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
