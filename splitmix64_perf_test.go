package icmp_tun

import (
	"math/rand"
	"testing"
)

func BenchmarkSplitMix64_XORKeyStream(b *testing.B) {
	data := make([]byte, 1024*1024*512)
	_, _ = rand.Read(data)
	sm := SplitMix64(rand.Uint64())
	b.SetBytes(1)
	b.ResetTimer()

	for remain := b.N; remain > 0; remain -= len(data) {
		n := remain
		if n > len(data) {
			n = len(data)
		}
		sm.XORKeyStream(data[:n], data[:n])
	}
}

/*
// slow
BenchmarkSplitMix64_XORKeyStream-4   	944828324	         1.30 ns/op
// unsafe uint64
BenchmarkSplitMix64_XORKeyStream-4   	1000000000	         0.359 ns/op
// []uint64 no bound check
BenchmarkSplitMix64_XORKeyStream-4   	1000000000	         0.343 ns/op
// ptr no bounds check
BenchmarkSplitMix64_XORKeyStream-4   	1000000000	         0.331 ns/op
*/
