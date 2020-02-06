package icmp_tun

import (
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func TestSplitMix64_XORKeyStream_Short(t *testing.T) {
	expected := [...][]byte{
		{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x26, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x31, 0x7e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0xb2, 0x71, 0x52, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x4f, 0xd8, 0xf0, 0x4d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0xcc, 0x81, 0x18, 0xd2, 0x29, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x13, 0x18, 0x7, 0x23, 0xf2, 0x36, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x1b, 0x7c, 0x2c, 0xe0, 0x6, 0xe7, 0x5c, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0xfa, 0x2a, 0xa8, 0x54, 0xa2, 0xf6, 0x5e, 0xe4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x46, 0x57, 0xf5, 0xb5, 0xe7, 0x2b, 0x7b, 0xfd, 0x54, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0xd1, 0xc6, 0x75, 0xc5, 0x70, 0x4f, 0x2, 0xd1, 0xa7, 0x9d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x23, 0x54, 0x80, 0xe1, 0x8e, 0x0, 0x47, 0xf6, 0xec, 0x71, 0x51, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x6b, 0x73, 0xe4, 0x77, 0xed, 0xae, 0x1b, 0x52, 0x60, 0x39, 0x93, 0xf4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x67, 0xd7, 0x16, 0x3a, 0x45, 0xd7, 0xa4, 0x4e, 0x9a, 0x44, 0xa, 0xb, 0x65, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x19, 0x86, 0x4d, 0xd7, 0xd4, 0x30, 0xc0, 0x3a, 0x87, 0xf, 0xa4, 0xcb, 0x10, 0xae, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x4e, 0xbd, 0x1b, 0xae, 0x4, 0x2b, 0x42, 0x90, 0x92, 0x97, 0xe9, 0xe2, 0x4, 0x38, 0x3e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x77, 0x96, 0xf8, 0xb, 0xf2, 0x70, 0x2b, 0x48, 0xd5, 0xe2, 0x52, 0xba, 0xf7, 0xde, 0xe1, 0x53, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x5a, 0xc4, 0x92, 0x8e, 0xd7, 0x4a, 0x12, 0x2e, 0xb, 0xbd, 0x79, 0x9f, 0xd8, 0x29, 0xc0, 0xd6, 0x4f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x5a, 0xe, 0xa2, 0x9b, 0xdf, 0x85, 0x62, 0x3d, 0xb7, 0xba, 0x7c, 0x2c, 0x5d, 0x23, 0x81, 0xbf, 0x5d, 0x7a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0xb6, 0x12, 0x1a, 0x9d, 0x29, 0x9a, 0x8, 0x41, 0x2f, 0x7f, 0x14, 0x50, 0xa4, 0xb8, 0x9f, 0xe, 0x65, 0x7, 0xa4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0xf2, 0x1, 0x85, 0x98, 0x71, 0x5f, 0x66, 0x6e, 0x30, 0x8d, 0xc8, 0x35, 0xc8, 0x84, 0xbc, 0xb, 0xa5, 0x39, 0xdc, 0x5f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x86, 0x54, 0x92, 0x44, 0x1d, 0xab, 0xf4, 0xb3, 0xbd, 0x35, 0x21, 0xd8, 0xc5, 0x3b, 0x3d, 0xba, 0x7a, 0x76, 0xd7, 0xc0, 0x70, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x15, 0x8a, 0xdd, 0x8, 0x61, 0xe5, 0xfd, 0xd2, 0x93, 0x38, 0x89, 0x6, 0xec, 0x7, 0x95, 0x26, 0x7b, 0x2a, 0xf1, 0x55, 0xec, 0x95, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0xaf, 0xdf, 0x51, 0x6, 0xd, 0x96, 0xca, 0x44, 0x30, 0x4a, 0x73, 0xb0, 0x3a, 0x6, 0x34, 0xf1, 0xb8, 0x1d, 0xeb, 0x34, 0x0, 0xf8, 0xb, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x7, 0xc2, 0xbf, 0xc7, 0x46, 0x26, 0x15, 0xa6, 0x48, 0x12, 0x2d, 0x1, 0x44, 0x2a, 0x30, 0xb, 0x95, 0x3a, 0x98, 0xca, 0xf9, 0x8b, 0x1a, 0xc7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0xd8, 0x18, 0x4a, 0xa1, 0x1f, 0xae, 0xf0, 0xe1, 0x70, 0x4b, 0x4a, 0x40, 0x14, 0xff, 0xe9, 0x23, 0x47, 0x3b, 0xb7, 0xc9, 0x8d, 0x1e, 0x65, 0x5c, 0x92, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x12, 0x8f, 0x89, 0xfa, 0x76, 0xd7, 0x6f, 0xfa, 0xdd, 0x69, 0xb3, 0x4f, 0x10, 0x30, 0x36, 0xa7, 0xea, 0x74, 0x4e, 0xc3, 0x72, 0x89, 0x4f, 0xd5, 0x9, 0x53, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x56, 0x22, 0x4d, 0xf0, 0xf4, 0x5d, 0x7a, 0xa2, 0x9a, 0xea, 0x60, 0xf, 0x71, 0x28, 0x79, 0x16, 0x73, 0xe8, 0x82, 0x9f, 0x7d, 0x46, 0xb, 0x88, 0x13, 0x19, 0x3f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x3a, 0x62, 0x20, 0x5f, 0xc3, 0xf4, 0xeb, 0xa7, 0xf0, 0x80, 0xe3, 0x4b, 0x7a, 0x2a, 0x14, 0x12, 0xdb, 0xba, 0xee, 0x49, 0xe6, 0xeb, 0x6c, 0x22, 0x5, 0xfc, 0x44, 0xb0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0xe3, 0xfa, 0xff, 0xb8, 0x5d, 0x98, 0x4c, 0xf8, 0xab, 0x30, 0x15, 0xc7, 0xd2, 0x44, 0x28, 0xd1, 0xdc, 0x59, 0x1e, 0xe7, 0xe0, 0xf8, 0xa4, 0x93, 0x15, 0xfe, 0x40, 0xa3, 0x15, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x5b, 0x32, 0x2, 0x44, 0xfd, 0xbe, 0x27, 0xc4, 0x16, 0x6c, 0x7a, 0x7, 0xcc, 0xbc, 0x7a, 0x1d, 0x9d, 0x47, 0xe, 0x98, 0x91, 0x4c, 0x69, 0x49, 0xa3, 0x73, 0xcf, 0xfb, 0xf7, 0x2c, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0xb1, 0x82, 0xed, 0x28, 0xa, 0x7c, 0xb5, 0xd1, 0x96, 0x5e, 0xa4, 0x41, 0x9c, 0x9d, 0xdc, 0x7d, 0xa3, 0x9, 0xa0, 0x61, 0x25, 0x72, 0x3e, 0xd8, 0xde, 0x9e, 0xe0, 0x8d, 0xc4, 0xb1, 0x4f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x8e, 0x3a, 0x8c, 0x84, 0xea, 0x29, 0xb9, 0x17, 0x35, 0x39, 0x37, 0x4a, 0x6c, 0x95, 0xc3, 0xc7, 0x47, 0xfb, 0x61, 0x4d, 0x7c, 0x70, 0x1a, 0xe5, 0xe8, 0x82, 0x80, 0xc1, 0xa1, 0xf3, 0x4, 0x31, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
	}
	for i, exp := range expected {
		data := make([]byte, 50)
		sm := SplitMix64(fmix64(uint64(11111 + i)))
		sm.XORKeyStream(data[:i], data[:i])
		assert.Equal(t, exp, data)
		assert.Equal(t, byte(0), data[i])
	}
}

func TestSplitMix64_XORKeyStream_Long(t *testing.T) {
	expected := [...][]byte{
		{0x10, 0x33, 0x49, 0x78, 0xfa, 0x63, 0x93, 0x5b, 0xee, 0xc7, 0x8f, 0xe6, 0x74, 0xe8, 0x15, 0x79, 0x70, 0xe2, 0x43, 0x7d, 0x5e, 0x6f, 0x2d, 0xc4, 0x75, 0xaf, 0x21, 0x81, 0x46, 0xf7, 0x75, 0x68, 0x70, 0x8d, 0xe0, 0xa1, 0x34, 0xc5, 0xa, 0x62, 0xf7, 0x59, 0xd2, 0xff, 0x2f, 0x78, 0x99, 0x2f, 0x65, 0x15, 0x25, 0x38, 0x56, 0xd1, 0xcd, 0x9f, 0xa0, 0xf8, 0xdf, 0xf0, 0x98, 0xf8, 0x8e, 0x72, 0x97, 0xa4, 0x3c, 0x67, 0xfb, 0xba, 0x50, 0x66, 0xb2, 0xc7, 0xc, 0x94, 0x7b, 0xe5, 0xfc, 0x65, 0xa9, 0x5c, 0x8f, 0xc6, 0x72, 0x54, 0x3, 0x6d, 0xfe, 0x79, 0xbe, 0x98, 0x67, 0xf9, 0x11, 0x8d, 0xdd, 0x81, 0x4e, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x26, 0xb5, 0x50, 0x28, 0x7d, 0x10, 0xe3, 0x6, 0x1e, 0x76, 0xdf, 0x90, 0x45, 0xae, 0x92, 0x7a, 0xf2, 0xfd, 0x66, 0x99, 0xa, 0x2, 0x6a, 0x6, 0x99, 0x77, 0x6d, 0x4d, 0xee, 0xaf, 0xe0, 0x21, 0xa1, 0x1a, 0xad, 0x78, 0x3c, 0xeb, 0xc9, 0x52, 0x6e, 0x2a, 0xd0, 0x85, 0x91, 0xaf, 0x96, 0xaf, 0xc7, 0xf2, 0x5a, 0x48, 0x2e, 0x3c, 0x7d, 0xb6, 0xd9, 0xb9, 0xd, 0xaf, 0x71, 0x84, 0x9f, 0x5b, 0xb2, 0xef, 0x94, 0x66, 0xef, 0x11, 0x59, 0x93, 0x7c, 0x4e, 0x50, 0xb, 0x2, 0x24, 0x56, 0xbb, 0xed, 0xe9, 0x3f, 0x71, 0xc6, 0xa9, 0xf, 0x35, 0xc7, 0xe2, 0xb4, 0x8d, 0xe7, 0x47, 0x62, 0xe1, 0xf7, 0x68, 0xa3, 0x8d, 0x46, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x31, 0x7e, 0xb3, 0x1f, 0x69, 0xe, 0x1f, 0x8c, 0x74, 0xbb, 0x3, 0xaf, 0x86, 0xa6, 0xef, 0x78, 0x0, 0x9c, 0xec, 0xcb, 0xd3, 0xb8, 0x8, 0xa6, 0xa9, 0x55, 0x4d, 0x3c, 0x7b, 0x51, 0xa2, 0xa1, 0xa, 0x63, 0xec, 0x7d, 0xad, 0x1d, 0x61, 0x22, 0x1d, 0xe4, 0xbe, 0x43, 0x15, 0xe5, 0xc9, 0xc3, 0x8a, 0x23, 0x5e, 0x57, 0x53, 0x6a, 0x1b, 0x3, 0x66, 0x70, 0x16, 0x31, 0xfb, 0x3f, 0xe7, 0x55, 0x80, 0xe5, 0x76, 0x75, 0x64, 0x59, 0x13, 0x8c, 0x52, 0xd9, 0xa8, 0xb7, 0x9f, 0x49, 0xaf, 0x2, 0xde, 0xf0, 0x5e, 0xc4, 0x7b, 0x46, 0xe1, 0xf, 0xe8, 0x8a, 0x14, 0x5f, 0xb8, 0xba, 0xc4, 0xb, 0xa2, 0x56, 0x54, 0x14, 0x4d, 0xd6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
	}
	for i, exp := range expected {
		data := make([]byte, 120)
		sm := SplitMix64(fmix64(uint64(11111 + i)))
		sm.XORKeyStream(data[:100+i], data[:100+i])
		assert.Equal(t, exp, data)
		assert.Equal(t, byte(0), data[100+i])
	}
}

func BenchmarkSplitMix64_XORKeyStream_Big(b *testing.B) {
	data := make([]byte, 1024*1024*512)
	_, _ = rand.Read(data)
	sm := SplitMix64(rand.Uint64())
	b.SetBytes(1)
	b.ResetTimer()

	//c1 := gotsc.BenchStart()
	for remain := b.N; remain > 0; remain -= len(data) {
		n := remain
		if n > len(data) {
			n = len(data)
		}
		sm.XORKeyStream(data[:n], data[:n])
	}
	//cycles := gotsc.BenchEnd() - c1
	//b.StopTimer()
	//b.Logf("cycles per loop: %v", float64(cycles)/float64(b.N)*16)
}

func BenchmarkSplitMix64_XORKeyStream_1k(b *testing.B) {
	data := make([]byte, 1000)
	_, _ = rand.Read(data)
	sm := SplitMix64(rand.Uint64())

	//overhead := gotsc.TSCOverhead()

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	//c1 := gotsc.BenchStart()
	for i := 0; i < b.N; i++ {
		sm.XORKeyStream(data, data)
	}
	//cycles := gotsc.BenchEnd() - c1 - overhead
	//b.StopTimer()
	//b.Logf("cycles per loop: %v", float64(cycles)/float64(b.N*len(data))*16)
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
// asm
BenchmarkSplitMix64_XORKeyStream-4   	1000000000	         0.292 ns/op	3424.46 MB/s
// asm unroll factor 2
BenchmarkSplitMix64_XORKeyStream-4   	1000000000	         0.230 ns/op	4347.58 MB/s
// asm unroll factor 4
BenchmarkSplitMix64_XORKeyStream-4   	1000000000	         0.250 ns/op	3999.77 MB/s
// asm no unroll
BenchmarkSplitMix64_XORKeyStream-4   	1000000000	         0.237 ns/op	4219.17 MB/s
BenchmarkSplitMix64_XORKeyStream-4   	1000000000	         0.242 ns/op	4131.99 MB/s
// lea factor 4 negative index
BenchmarkSplitMix64_XORKeyStream_Big-4   	1000000000	         0.201 ns/op	4974.84 MB/s
*/

/*
// no unroll
BenchmarkSplitMix64_XORKeyStream_1k-4   	 5084454	       249 ns/op	4022.28 MB/s
    splitmix64_test.go:107: cycles per loop: 10.31976248855826
// unroll factor 2
BenchmarkSplitMix64_XORKeyStream_1k-4   	 5205288	       232 ns/op	4308.77 MB/s
    splitmix64_test.go:107: cycles per loop: 9.634580068576417
// unroll factor 3
BenchmarkSplitMix64_XORKeyStream_1k-4   	 4917750	       234 ns/op	4276.06 MB/s
    splitmix64_test.go:107: cycles per loop: 9.711373271109755
// unroll factor 4
BenchmarkSplitMix64_XORKeyStream_1k-4   	 4742810	       231 ns/op	4331.09 MB/s
    splitmix64_test.go:107: cycles per loop: 9.57790378952562

// lea factor 1
BenchmarkSplitMix64_XORKeyStream_1k-4   	 4705612	       254 ns/op	3937.53 MB/s
// lea factor 2
BenchmarkSplitMix64_XORKeyStream_1k-4   	 5239874	       225 ns/op	4447.86 MB/s
// lea factor 4
BenchmarkSplitMix64_XORKeyStream_1k-4   	 5172118	       210 ns/op	4762.27 MB/s
// lea factor 4 constant
BenchmarkSplitMix64_XORKeyStream_1k-4   	 5713958	       203 ns/op	4917.07 MB/s
// lea factor 4 negative index
BenchmarkSplitMix64_XORKeyStream_1k-4   	 5882018	       196 ns/op	5114.51 MB/s
*/
