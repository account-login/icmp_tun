package icmp_tun

import (
	"unsafe"
)

// from https://en.wikipedia.org/wiki/Xorshift
type SplitMix64 uint64

func (s *SplitMix64) next() uint64 {
	result := uint64(*s)
	*s = SplitMix64(result + 0x9E3779B97f4A7C15)
	result = (result ^ (result >> 30)) * 0xBF58476D1CE4E5B9
	result = (result ^ (result >> 27)) * 0x94D049BB133111EB
	return result ^ (result >> 31)
}

func (s *SplitMix64) unalignedXORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	_ = dst[len(src)-1]

	wend := len(src) & (^7)
	for i := 0; i < wend; i += 8 {
		r := s.next()
		*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&dst[0])) + uintptr(i))) =
			r ^ *(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&src[0])) + uintptr(i)))
	}

	if len(src)%8 > 0 {
		r := s.next()
		for bi := wend; bi < len(src); bi++ {
			dst[bi] = src[bi] ^ byte(r)
			r >>= 8
		}
	}
}

func (s *SplitMix64) genericXORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	_ = dst[len(src)-1]

	for i := 0; i < len(src); i += 8 {
		r := s.next()
		// Huff's device generates bad asm in Go
		for j := i; j < len(src) && j < i+8; j++ {
			dst[j] = src[j] ^ byte(r)
			r >>= 8
		}
	}
}
