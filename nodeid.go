package icmp_tun

import (
	"context"
	"encoding/binary"
	"gopkg.in/account-login/ctxlog.v2"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

// from https://stackoverflow.com/a/37382208
// Get preferred outbound ip of this machine
func GetOutboundIPV4(ctx context.Context) net.IP {
	conn, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		ctxlog.Errorf(ctx, "net.Dial: %v", err)
		return nil
	}
	defer SafeClose(ctx, conn)

	return conn.LocalAddr().(*net.UDPAddr).IP
}

func ParseNodeID(ctx context.Context, id string) uint32 {
	if strings.ToLower(id) == "ip" {
		ip := GetOutboundIPV4(ctx)
		if ip == nil || ip.IsUnspecified() || len(ip) != 4 {
			return 0
		}

		return binary.BigEndian.Uint32(ip)
	}

	if strings.ToLower(id) == "rand" {
		return rand.New(rand.NewSource(time.Now().UnixNano())).Uint32()
	}

	if ip := net.ParseIP(id).To4(); ip != nil {
		return binary.BigEndian.Uint32(ip)
	}

	if i, err := strconv.ParseUint(id, 0, 32); err == nil {
		return uint32(i)
	}
	return 0
}
