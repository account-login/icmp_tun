package icmp_tun

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFMix64(t *testing.T) {
	assert.Equal(t, uint64(123), ximf64(fmix64(123)))
}
