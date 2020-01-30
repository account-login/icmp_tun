package icmp_tun

import (
	"context"
	"gopkg.in/account-login/ctxlog.v2"
	"io"
	"os"
	"time"
)

func SafeClose(ctx context.Context, closer io.Closer) {
	if err := closer.Close(); err != nil {
		ctxlog.Errorf(ctx, "close: %v", err)
	}
}

var procPID = os.Getpid()

func Rand64ByTime() uint64 {
	return fmix64(uint64(time.Now().UnixNano() ^ int64(procPID)))
}
