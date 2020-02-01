package main

import (
	"context"
	"flag"
	"github.com/account-login/icmp_tun"
	"gopkg.in/account-login/ctxlog.v2"
	"log"
	"os"
	"os/signal"
	"runtime"
)

func main() {
	// logging
	log.SetFlags(log.Flags() | log.Lmicroseconds)

	// ctx
	ctx := context.Background()

	// args
	local := icmp_tun.Local{}
	flag.StringVar(&local.Local, "local", "127.0.0.1:5353", "local UDP listener")
	flag.StringVar(&local.Remote, "remote", "1.2.3.4", "remote ip")
	flag.BoolVar(&local.Verbose, "verbose", false, "verbose log")
	localIDArg := flag.String("local-id", "", "local node ID")
	remoteIDArg := flag.String("remote-id", "", "remote node ID")
	noObfsArg := flag.Bool("no-obfs", false, "disable obfuscation")
	logFileArg := flag.String("log", "", "log file")
	flag.Parse()

	// log
	if *logFileArg != "" {
		f, err := os.OpenFile(*logFileArg, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err == nil {
			log.SetOutput(f)
		}
		// leak f
	}

	// node-id
	local.LocalID = icmp_tun.ParseNodeID(ctx, *localIDArg)
	local.RemoteID = icmp_tun.ParseNodeID(ctx, *remoteIDArg)
	if local.LocalID == 0 || local.RemoteID == 0 {
		ctxlog.Errorf(ctx, "invalid node id [local-id:%v][remote-id:%v]", *localIDArg, *remoteIDArg)
		os.Exit(1)
		return
	}

	// obfs
	if *noObfsArg {
		local.Obfuscator = icmp_tun.NilObfs{}
	} else {
		local.Obfuscator = icmp_tun.NewSM64CRC32Obfs()
	}

	// sigint
	ctx, cancel := context.WithCancel(ctx)
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	go func() {
		<-sigint
		ctxlog.Noticef(ctx, "sigint received, stopping")
		cancel()
	}()

	// log
	ctxlog.Infof(ctx, "starting with [local-id:0x%08X][remote-id:0x%08X] [ngoroutine:%v]",
		local.LocalID, local.RemoteID, runtime.NumGoroutine())

	// run
	if err := local.Run(ctx); err != nil && err != context.Canceled {
		ctxlog.Errorf(ctx, "run: %v", err)
		os.Exit(2)
		return
	}
	ctxlog.Noticef(ctx, "stopped [ngoroutine:%v]", runtime.NumGoroutine())
}
