package icmp_tun

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRingBitmap_Set_A(t *testing.T) {
	bitsize := uint32(64)
	bm := NewRingBitmap(bitsize)
	assert.Equal(t, bitsize-1, bm.mask)
	assert.Equal(t, []uint32{0, 0}, bm.data)
	c, s := bm.Count(0, 0)
	assert.Equal(t, uint32(0), c)
	assert.Equal(t, uint32(0), s)

	// first
	bm.Set(11 + bitsize)
	assert.Equal(t, uint32(11+bitsize), bm.first)
	assert.Equal(t, uint32(11), bm.last)
	assert.Equal(t, []uint32{0b00001000_00000000, 0}, bm.data)
	c, s = bm.Count(0, 11+bitsize)
	assert.Equal(t, uint32(1), c)
	assert.Equal(t, uint32(1), s)

	// second
	bm.Set(12 + bitsize)
	assert.Equal(t, uint32(11+bitsize), bm.first)
	assert.Equal(t, uint32(12), bm.last)
	assert.Equal(t, []uint32{0b00011000_00000000, 0}, bm.data)
	c, s = bm.Count(0, 12+bitsize)
	assert.Equal(t, uint32(2), c)
	assert.Equal(t, uint32(2), s)

	// skip
	bm.Set(14 + bitsize)
	assert.Equal(t, []uint32{0b01011000_00000000, 0}, bm.data)
	bm.Set(33 + bitsize)
	assert.Equal(t, []uint32{0b01011000_00000000, 0b10}, bm.data)
	c, s = bm.Count(0, 33+bitsize)
	assert.Equal(t, uint32(4), c)
	assert.Equal(t, uint32(23), s)

	// full
	assert.Equal(t, uint32(11+bitsize), bm.first)
	bm.Set(11 + bitsize*2)
	assert.Equal(t, kBitmapFull, bm.first)
	assert.Equal(t, []uint32{0b01011000_00000000, 0b10}, bm.data)
	c, s = bm.Count(12+bitsize, 11+bitsize*2)
	assert.Equal(t, uint32(4), c)
	assert.Equal(t, bitsize, s)
}

func TestRingBitmap_Set_B(t *testing.T) {
	bitsize := uint32(64)
	bm := NewRingBitmap(bitsize)
	assert.Equal(t, bitsize-1, bm.mask)
	assert.Equal(t, []uint32{0, 0}, bm.data)

	// first
	bm.Set(11 + bitsize)
	assert.Equal(t, uint32(11+bitsize), bm.first)
	assert.Equal(t, uint32(11), bm.last)
	assert.Equal(t, []uint32{0b00001000_00000000, 0}, bm.data)
	// out of order first
	bm.Set(5 + bitsize)
	assert.Equal(t, uint32(5+bitsize), bm.first)
	assert.Equal(t, []uint32{0b00001000_00100000, 0}, bm.data)

	bm.Set(7 + bitsize)
	assert.Equal(t, uint32(5+bitsize), bm.first)
	assert.Equal(t, []uint32{0b00001000_10100000, 0}, bm.data)
}

func TestRingBitmap_Set_Skip(t *testing.T) {
	bitsize := uint32(32 * 8)
	bm := NewRingBitmap(bitsize)

	for i := uint32(0); i < bitsize; i++ {
		bm.Set(i)
	}
	bm.Set(bitsize)
	assert.Equal(t, kBitmapFull, bm.first)
	assert.Equal(t, uint32(0), bm.Last())
	assert.Equal(t, uint32(0xffffffff), bm.data[0])

	// skip
	bm.Set(bitsize + 2)
	assert.Equal(t, uint32(0xffffff00|0b11111101), bm.data[0])
	bm.Set(bitsize + 5)
	assert.Equal(t, uint32(0xffffff00|0b11100101), bm.data[0])
	assert.Equal(t, uint32(0xffffffff), bm.data[1])
	bm.Set(bitsize + 32 + 7)
	assert.Equal(t, uint32(0b00100101), bm.data[0])
	assert.Equal(t, uint32(0xffffff00|0b10000000), bm.data[1])
	bm.Set(bitsize + 32 + 32 + 32 + 9)
	assert.Equal(t, uint32(0b10000000), bm.data[1])
	assert.Equal(t, uint32(0), bm.data[2])
	assert.Equal(t, uint32(0xffff0000|0b11111110_00000000), bm.data[3])
	assert.Equal(t, uint32(32+32+32+9), bm.Last())

	// out of order
	bm.Set(bitsize + 32 + 32 + 32 + 7)
	assert.Equal(t, uint32(0xffff0000|0b11111110_10000000), bm.data[3])
	assert.Equal(t, uint32(32+32+32+9), bm.Last())

	c, s := bm.Count(bitsize, bitsize+32+32+32+9)
	assert.Equal(t, uint32(6), c)
	assert.Equal(t, uint32(32+32+32+9+1), s)
}
