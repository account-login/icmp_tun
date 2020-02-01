package icmp_tun

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func TestSM64CRC32Obfs_NoHeader(t *testing.T) {
	obfs := NewSM64CRC32Obfs()

	for size := 0; size < 2000; size++ {
		// generate data
		data := make([]byte, size)
		_, _ = rand.Read(data)
		cpy := make([]byte, size)
		copy(cpy, data)
		// encode
		encoded := obfs.Encode(nil, data)
		// data not overwritten
		assert.True(t, bytes.Equal(cpy, data))
		// decode
		decoded, err := obfs.Decode([]byte{}, encoded)
		assert.NoError(t, err)
		assert.Equal(t, cpy, decoded)
		assert.True(t, bytes.Equal(cpy, decoded))
	}
}

func TestSM64CRC32Obfs_ReuseHeader(t *testing.T) {
	obfs := NewSM64CRC32Obfs()

	hs := 10
	buf := make([]byte, hs+obfs.HeaderSize()+2000)
	for i := 0; i < hs; i++ {
		buf[i] = byte(i)
	}
	header := buf[:hs]
	hcpy := make([]byte, len(header))
	copy(hcpy, header)

	for size := 0; size < 2000; size++ {
		// generate data
		data := make([]byte, size)
		_, _ = rand.Read(data)
		cpy := make([]byte, size)
		copy(cpy, data)
		// encode
		encoded := obfs.Encode(header, data)
		// data not overwritten
		assert.True(t, bytes.Equal(cpy, data))
		// reuse header buf
		assert.Equal(t, &buf[0], &encoded[0])
		// header not overwritten
		assert.True(t, bytes.Equal(hcpy, encoded[:hs]))
		// decode
		decoded, err := obfs.Decode([]byte{}, encoded[hs:])
		assert.NoError(t, err)
		assert.Equal(t, cpy, decoded)
		assert.True(t, bytes.Equal(cpy, decoded))
	}
}
