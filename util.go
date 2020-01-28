package icmp_tun

import (
	"context"
	"gopkg.in/account-login/ctxlog.v2"
	"io"
)

func SafeClose(ctx context.Context, closer io.Closer) {
	if err := closer.Close(); err != nil {
		ctxlog.Errorf(ctx, "close: %v", err)
	}
}
