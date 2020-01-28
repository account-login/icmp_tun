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
	remote := icmp_tun.Remote{}
	flag.StringVar(&remote.Target, "target", "8.8.8.8:53", "UDP target")
	flag.BoolVar(&remote.Verbose, "verbose", false, "verbose log")
	nodeIDArg := flag.String("node-id", "", "self node ID")
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
	remote.NodeId = icmp_tun.ParseNodeID(ctx, *nodeIDArg)
	if remote.NodeId == 0 {
		ctxlog.Errorf(ctx, "invalid node-id: %v", *nodeIDArg)
		os.Exit(1)
		return
	}

	// obfs
	if *noObfsArg {
		remote.Obfuscator = icmp_tun.NilObfs{}
	} else {
		remote.Obfuscator = icmp_tun.NewRC4CRC32Obfs()
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
	ctxlog.Infof(ctx, "starting with [node-id:0x%08X] [ngoroutine:%v]",
		remote.NodeId, runtime.NumGoroutine())

	// run
	if err := remote.Run(ctx); err != nil && err != context.Canceled {
		ctxlog.Errorf(ctx, "run: %v", err)
		os.Exit(2)
		return
	}
	ctxlog.Noticef(ctx, "stopped [ngoroutine:%v]", runtime.NumGoroutine())
}
