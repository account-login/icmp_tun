package icmp_tun

import (
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math/rand"
	"time"
)

type Obfuscator interface {
	Encode([]byte) []byte
	Decode([]byte) ([]byte, error)
}

type NilObfs struct{}

func (NilObfs) Encode(in []byte) []byte {
	return in
}

func (NilObfs) Decode(in []byte) ([]byte, error) {
	return in, nil
}

type RC4CRC32Obfs struct {
	rand *rand.Rand
}

func padLen(origin int, rand *rand.Rand) int {
	const padLimit = 1000
	if origin >= padLimit {
		return 0
	}
	return rand.Intn(padLimit - origin)
}

func NewRC4CRC32Obfs() *RC4CRC32Obfs {
	return &RC4CRC32Obfs{rand.New(rand.NewSource(time.Now().UnixNano()))}
}

// from https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
func fmix64(h uint64) uint64 {
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

// from https://stackoverflow.com/a/9758173/3886899
func ximf64(h uint64) uint64 {
	h ^= h >> 33
	h *= 11291846944257947611
	h ^= h >> 33
	h *= 5725274745694666757
	h ^= h >> 33
	return h
}

// u16		u16		u32
// pad		rand	crc32
// ----------T-----------
//           |
//         fmix64
//           |
//         rc4 key        xc4 payload padding
// ---------------------- ----------- -------
func (o RC4CRC32Obfs) Encode(in []byte) []byte {
	pad := padLen(len(in), o.rand)
	buf := make([]byte, 8+len(in)+pad)

	// padding
	o.rand.Read(buf[8+len(in):])

	// crc32 of payload
	hasher := crc32.NewIEEE()
	_, _ = hasher.Write(in)
	hash := hasher.Sum32()

	// header
	r := uint64(pad)
	r |= uint64(o.rand.Intn(0x10000)) << 16
	r |= uint64(hash) << 32
	binary.LittleEndian.PutUint64(buf[:8], fmix64(r))

	// body
	cipher, _ := rc4.NewCipher(buf[:8])
	cipher.XORKeyStream(buf[8:], in)

	return buf
}

func (RC4CRC32Obfs) Decode(in []byte) ([]byte, error) {
	if len(in) < 8 {
		return nil, fmt.Errorf("packet length %v < 8", len(in))
	}

	// pad
	r := ximf64(binary.LittleEndian.Uint64(in[:8]))
	pad := r & 0xffff
	bodyLen := len(in) - 8 - int(pad)
	if bodyLen < 0 {
		return nil, fmt.Errorf("bad packet: packet length:%v padding length:%v",
			len(in), pad)
	}

	// payload
	cipher, _ := rc4.NewCipher(in[:8])
	cipher.XORKeyStream(in[8:8+bodyLen], in[8:8+bodyLen])

	// crc32
	hash := uint32(r >> 32)
	hasher := crc32.NewIEEE()
	_, _ = hasher.Write(in[8 : 8+bodyLen])
	if calc := hasher.Sum32(); calc != hash {
		return nil, fmt.Errorf("crc32 mismatch: [calc:%v] != [header:%v]",
			calc, hash)
	}

	return in[8 : 8+bodyLen], nil
}
