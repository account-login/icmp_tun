package icmp_tun

import (
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

var gTestU16 uint16

//func TestSum16b32(t *testing.T) {
//	data := [32]byte{
//		1, 1,
//		10, 0,
//		100, 0,
//		2, 0,
//		20, 0,
//		5, 0,
//		50, 0,
//		9, 2,
//	}
//	sum := sum16b32(&data[0], int64(len(data)))
//	assert.Equal(t, uint32(197+256*3), sum)
//}

func TestChecksum(t *testing.T) {
	results := [...]uint16{
		0x453c,
		0xa088,
		0x5a4e,
		0x70f4,
		0xc668,
		0xe36b,
		0x9d35,
		0x7141,
		0x807,
		0x7312,
		0xf3bf,
		0xb197,
		0xd4c3,
		0x6beb,
		0x7b2d,
		0xe51d,
		0x2f7e,
		0xa8dd,
		0x6c85,
		0x3dd0,
		0x361b,
		0x6418,
		0x48b1,
		0x51eb,
		0x27d0,
		0x3eb,
		0xef6d,
		0x5098,
		0xc4d8,
		0x32a8,
		0x7a0d,
		0xb014,
		0x3bf7,
		0x8ab8,
		0x7ec,
		0x3645,
		0xeaa8,
		0xf7e5,
	}

	for i, r := range results {
		data := make([]byte, 12345+i)
		rng := rand.New(rand.NewSource(123 + int64(i)))
		_, _ = rng.Read(data)

		assert.Equal(t, r, checksum(data))
	}
}

func BenchmarkChecksum_Long(b *testing.B) {
	data := make([]byte, 1024*1024*512)
	b.SetBytes(1)
	b.ResetTimer()
	for remain := b.N; remain > 0; remain -= len(data) {
		b.StopTimer()
		_, _ = rand.Read(data)
		n := remain
		if n > len(data) {
			n = len(data)
		}
		b.StartTimer()

		gTestU16 += checksum(data[:n])
	}
}

func BenchmarkChecksum_1k(b *testing.B) {
	data := make([]byte, 1000)
	_, _ = rand.Read(data)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		gTestU16 += checksum(data)
	}
}

/*
// naive
BenchmarkChecksum-4   	1000000000	         0.372 ns/op	2688.02 MB/s
// sse factor 2
BenchmarkChecksum-4   	1000000000	         0.0910 ns/op	10988.38 MB/s
// sse factor 4
BenchmarkChecksum-4   	1000000000	         0.0780 ns/op	12819.79 MB/s
*/

/*
// factor 4
BenchmarkChecksum_1k-4   	18180770	        58.4 ns/op	17134.52 MB/s
// factor 3
BenchmarkChecksum_1k-4   	15999081	        74.4 ns/op	13443.84 MB/s
// factor 2
BenchmarkChecksum_1k-4   	15324738	        77.1 ns/op	12964.35 MB/s
// no unroll
BenchmarkChecksum_1k-4   	14035122	        84.3 ns/op	11863.33 MB/s
*/
