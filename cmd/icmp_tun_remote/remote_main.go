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
	"strconv"
	"strings"
)

func disablePing(ctx context.Context) func() {
	key := "net.ipv4.icmp_echo_ignore_all"
	origin, err := icmp_tun.SysctlGet(key)
	if err != nil {
		ctxlog.Errorf(ctx, "SysctlGet: %v", err)
		return nil
	}

	if i, err := strconv.Atoi(strings.TrimSpace(string(origin))); err != nil || i != 0 {
		ctxlog.Infof(ctx, "ping already disabled: %s = %s", key, origin)
		return nil
	}

	err = icmp_tun.SysctlSet(key, ([]byte)("1\n"))
	if err != nil {
		ctxlog.Errorf(ctx, "disable ping: SysctlSet: %v", err)
		return nil
	}

	ctxlog.Infof(ctx, "disabled ping [key:%s]", key)
	return func() {
		err = icmp_tun.SysctlSet(key, origin)
		if err != nil {
			ctxlog.Errorf(ctx, "re-enable ping: SysctlSet: %v", err)
		} else {
			ctxlog.Infof(ctx, "re-enabled ping [key:%s]", key)
		}
	}
}

func cmain() int {
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
	takeOverPingArg := flag.Bool("takeover-ping", false,
		"disable system echo reply and emulate echo reply")
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
		return 1
	}

	// obfs
	if *noObfsArg {
		remote.Obfuscator = icmp_tun.NilObfs{}
	} else {
		remote.Obfuscator = icmp_tun.NewSM64CRC32Obfs()
	}

	if *takeOverPingArg {
		if rollback := disablePing(ctx); rollback != nil {
			defer rollback()
			remote.EnableEcho = true
		}
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
		return 2
	}
	ctxlog.Noticef(ctx, "stopped [ngoroutine:%v]", runtime.NumGoroutine())
	return 0
}

func main() {
	os.Exit(cmain())
}
