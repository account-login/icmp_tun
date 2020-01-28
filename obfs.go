package icmp_tun

import (
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"github.com/account-login/icmp_tun/subtle"
	"hash/crc32"
	"math/rand"
	"time"
)

type Obfuscator interface {
	Encode(header []byte, data []byte) []byte
	Decode(dst []byte, src []byte) ([]byte, error)
	HeaderSize() int
}

type NilObfs struct{}

func (NilObfs) Encode(header []byte, data []byte) []byte {
	return append(header, data...)
}

func (NilObfs) Decode(dst []byte, src []byte) ([]byte, error) {
	// dst buf
	if cap(dst) < len(src) {
		dst = make([]byte, len(src))
	}
	dst = dst[:len(src)]

	copy(dst, src)
	return dst, nil
}

func (NilObfs) HeaderSize() int {
	return 0
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
func (obfs RC4CRC32Obfs) Encode(header []byte, data []byte) []byte {
	pad := padLen(len(data), obfs.rand)
	buflen := len(header) + HS + len(data) + pad
	var out []byte
	if cap(header) >= buflen {
		// reuse header buf
		buf := header[len(header):]
		if subtle.InexactOverlap(buf[HS:HS+len(data)], data) || subtle.AnyOverlap(buf[:HS], data) {
			panic("overlap")
		}
		out = header[:buflen]
	} else {
		// new buf
		out = make([]byte, buflen)
		copy(out, header)
	}
	// to be filled
	buf := out[len(header):buflen]

	// padding
	obfs.rand.Read(buf[HS+len(data):])

	// crc32 of payload
	hasher := crc32.NewIEEE()
	_, _ = hasher.Write(data)
	hash := hasher.Sum32()

	// header
	r := uint64(pad)
	r |= uint64(obfs.rand.Intn(0x10000)) << 16
	r |= uint64(hash) << 32
	binary.LittleEndian.PutUint64(buf[:HS], fmix64(r))

	// body
	cipher, _ := rc4.NewCipher(buf[:HS])
	cipher.XORKeyStream(buf[HS:], data)

	return out
}

func (RC4CRC32Obfs) Decode(dst []byte, src []byte) ([]byte, error) {
	if len(src) < HS {
		return nil, fmt.Errorf("packet length %v < %v", len(src), HS)
	}

	// pad
	r := ximf64(binary.LittleEndian.Uint64(src[:HS]))
	pad := r & 0xffff
	bodyLen := len(src) - HS - int(pad)
	if bodyLen < 0 {
		return nil, fmt.Errorf("bad packet: packet length:%v padding length:%v",
			len(src), pad)
	}

	// dst buf
	if cap(dst) < bodyLen {
		dst = make([]byte, bodyLen)
	}
	dst = dst[:bodyLen]

	// payload
	cipher, _ := rc4.NewCipher(src[:HS])
	cipher.XORKeyStream(dst, src[HS:HS+bodyLen])

	// crc32
	hash := uint32(r >> 32)
	hasher := crc32.NewIEEE()
	_, _ = hasher.Write(dst)
	if calc := hasher.Sum32(); calc != hash {
		return nil, fmt.Errorf("crc32 mismatch: [calc:%v] != [header:%v]",
			calc, hash)
	}

	return dst, nil
}

const HS = 8

func (RC4CRC32Obfs) HeaderSize() int {
	return HS
}
