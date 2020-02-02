// +build !appengine
// +build gc
// +build !noasm

package icmp_tun

//go:noescape
func sm64xorLU(s uint64, dst *uint8, src *uint8, n int64) uint64

func (s *SplitMix64) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	_ = dst[len(src)-1]
	r := sm64xorLU(uint64(*s), &dst[0], &src[0], int64(len(src)))
	*s = SplitMix64(r)
}
