// +build !amd64 appengine !gc noasm

package icmp_tun

import "runtime"

// unaligned and little endian
const kUALE = runtime.GOARCH == "386" || runtime.GOARCH == "amd64" || runtime.GOARCH == "ppc64le"

func (s *SplitMix64) XORKeyStream(dst, src []byte) {
	if kUALE {
		s.unalignedXORKeyStream(dst, src)
	} else {
		s.genericXORKeyStream(dst, src)
	}
}
