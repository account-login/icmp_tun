// +build !amd64 appengine !gc noasm

package icmp_tun

func checksum(b []byte) uint16 {
	return checksumGeneric(b)
}
