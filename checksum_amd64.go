// +build !appengine
// +build gc
// +build !noasm

package icmp_tun

//go:noescape
func sum16b32(b *byte, n int64) uint32

func checksum(b []byte) uint16 {
	// TODO: check cpuid for sse41
	s := sum16b32(&b[0], int64(len(b)))
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
}
