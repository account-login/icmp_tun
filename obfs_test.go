package icmp_tun

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func TestRC4CRC32Obfs(t *testing.T) {
	obfs := NewRC4CRC32Obfs()
	for size := 0; size < 2000; size++ {
		buf := make([]byte, size)
		_, _ = rand.Read(buf)
		cpy := make([]byte, size)
		copy(cpy, buf)
		encoded := obfs.Encode(buf)
		assert.True(t, bytes.Equal(cpy, buf))

		decoded, err := obfs.Decode(encoded)
		assert.NoError(t, err)
		assert.Equal(t, cpy, decoded)
		assert.True(t, bytes.Equal(cpy, decoded))
	}
}
