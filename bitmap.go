package icmp_tun

import (
	"math/bits"
)

type RingBitmap struct {
	last  uint32 // NOTE: not musked
	first uint32 // NOTE: not musked
	mask  uint32
	dmask uint32
	data  []uint32
}

const kBitmapEmpty = ^uint32(1)
const kBitmapFull = ^uint32(0)

func NewRingBitmap(bitSize uint32) *RingBitmap {
	if (bitSize-1)&bitSize != 0 {
		panic("bitSize must be 2^n")
	}
	if bitSize < 32 {
		panic("bitSize < 32")
	}
	// TODO: bitSize upper bound
	return &RingBitmap{
		last:  kBitmapEmpty,
		first: kBitmapEmpty,
		mask:  bitSize - 1,
		dmask: bitSize/32 - 1,
		data:  make([]uint32, bitSize/32),
	}
}

func (bm *RingBitmap) Clear() {
	bm.last = kBitmapEmpty
	bm.first = kBitmapEmpty
}

func (bm *RingBitmap) Init(bitSize uint32) {
	*bm = *NewRingBitmap(bitSize)
}

func (bm *RingBitmap) Last() uint32 {
	return bm.last
}

// [lo, hi]
func (bm *RingBitmap) Count(lo uint32, hi uint32) (ones uint32, total uint32) {
	if bm.first == kBitmapEmpty {
		return 0, 0
	}

	lo &= bm.mask
	hi &= bm.mask

	// bm.first is between [lo, hi]
	f := bm.first & bm.mask
	if bm.first != kBitmapFull && ((lo <= f && f <= hi) || (lo > hi && (f > lo || f < hi))) {
		lo = f
	}

	istart := lo / 32
	iend := hi / 32
	m1 := ^((uint32(1) << (lo % 32)) - 1)
	m2 := (uint32(1) << ((hi % 32) + 1)) - 1
	if istart == iend && lo <= hi {
		ones += uint32(bits.OnesCount32(bm.data[istart] & m1 & m2))
	} else {
		// count bits between (istart, iend)
		for i := (istart + 1) & bm.dmask; i != iend; i = (i + 1) & bm.dmask {
			ones += uint32(bits.OnesCount32(bm.data[i]))
		}
		// count bits on istart and iend
		ones += uint32(bits.OnesCount32(bm.data[istart] & m1))
		ones += uint32(bits.OnesCount32(bm.data[iend] & m2))
	}

	total = (hi - lo + 1) & bm.mask
	if total == 0 {
		total = bm.mask + 1
	}
	return
}

func (bm *RingBitmap) Set(seq uint32) {
	if bm.first != kBitmapFull {
		fdiff := seq - bm.first
		if bm.first == kBitmapEmpty || fdiff >= 1<<31 {
			// first seq, or out of order first seq
			bm.first = seq // NOTE: no mask
		} else if fdiff > bm.mask { // NOTE: seq and bm.first not musked here
			// full
			bm.first = kBitmapFull
		}
	}

	ldiff := (seq - bm.last) & bm.mask
	if bm.last != kBitmapEmpty && ldiff <= bm.mask/2 && ldiff > 1 {
		// seq > last + 1, unset bits in (last, seq)
		istart := (bm.last & bm.mask) / 32
		iend := (seq & bm.mask) / 32
		m1 := (uint32(1) << ((bm.last % 32) + 1)) - 1
		m2 := ^((uint32(1) << (seq % 32)) - 1)
		if istart == iend {
			bm.data[istart] &= m1 | m2
		} else {
			// clear uint32's between istart and iend
			for i := (istart + 1) & bm.dmask; i != iend; i = (i + 1) & bm.dmask {
				bm.data[i] = 0
			}
			// clear bits on istart and iend
			bm.data[istart] &= m1
			bm.data[iend] &= m2
		}
	}

	if bm.last == kBitmapEmpty || ldiff <= bm.mask/2 {
		// seq >= last, advance last seq
		bm.last = seq
	}

	// set current bit
	bm.data[(seq&bm.mask)/32] |= 1 << (seq % 32)
}
