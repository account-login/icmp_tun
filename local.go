package icmp_tun

import (
	"context"
	"encoding/binary"
	"github.com/pkg/errors"
	"golang.org/x/net/icmp"
	"gopkg.in/account-login/ctxlog.v2"
	"net"
	"sync/atomic"
	"time"
	"unsafe"
)

type Local struct {
	// node-id
	LocalID  uint32
	RemoteID uint32
	// local UDP listener
	Local string
	// remote ip
	Remote string
	// other
	Verbose    bool
	Obfuscator Obfuscator
	// states
	raddr    *net.IPAddr
	icmpconn *icmp.PacketConn
	lconn    *net.UDPConn
	pcaddr   unsafe.Pointer // client addr: *net.UDPConn
	pktid    uint32
	bm       *RingBitmap
	quiter   Quiter
}

func (l *Local) Run(ctx context.Context) error {
	if l.LocalID == 0 || l.RemoteID == 0 || l.Obfuscator == nil {
		return errors.New("c.LocalID == 0 || c.RemoteID == 0 || c.Obfuscator == nil")
	}

	// remote addr
	var err error
	l.raddr, err = net.ResolveIPAddr("ip4", l.Remote)
	if err != nil {
		return errors.Wrap(err, "resolve remote")
	}

	// local conn
	lconn, err := net.ListenPacket("udp", l.Local)
	if err != nil {
		return errors.Wrap(err, "listen on local")
	}
	defer SafeClose(ctx, lconn)
	l.lconn = lconn.(*net.UDPConn)

	// ICMP Conn
	l.icmpconn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return errors.Wrap(err, "listen for remote icmp")
	}
	defer SafeClose(ctx, l.icmpconn)

	// log
	ctxlog.Infof(ctx, "start listening [remote:%v][local:%v]", l.raddr, l.lconn.LocalAddr())

	// init states
	l.pktid = uint32(Rand64ByTime())
	l.bm = NewRingBitmap(kBitmapSize)
	l.quiter.Init()

	// convert ctx.Done() to quit flag
	go func() {
		<-ctx.Done()
		l.quiter.Quit()
	}()

	// run
	l.quiter.Go(func() { l.client2local(ctx) })
	l.quiter.Go(func() { l.remote2local(ctx) })
	l.quiter.Wait()

	// clean up
	ctxlog.Debugf(ctx, "stopping")

	// done
	return ctx.Err()
}

func (l *Local) client2local(ctx context.Context) {
	rn := Rand64ByTime()
	icmpid := uint16(rn)
	icmpseq := uint16(rn >> 16)
	ctxlog.Debugf(ctx, "ready to read from client [icmpid:%v]", icmpid)

	//   1B |   1B |     2B | 2B |  2B | 8B |  4B |  4B |
	// type | code | chksum | id | seq | HS | src | dst | data
	// -------------------------------
	//        ICMP ECHO HEADER
	hs := l.Obfuscator.HeaderSize()
	buf := make([]byte, 128*1024)
	buf[0] = ICMPTypeEcho
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[4:6], icmpid)
	icmpData := buf[ICMPEchoHeaderSize:]

	for {
		// test for quit flag
		if l.quiter.IsQuit() {
			break
		}

		// src dst cmd
		binary.LittleEndian.PutUint32(icmpData[hs+0:hs+4], l.LocalID)
		binary.LittleEndian.PutUint32(icmpData[hs+4:hs+8], l.RemoteID)
		binary.LittleEndian.PutUint32(icmpData[hs+8:hs+12], 0)

		// read from client
		_ = l.lconn.SetReadDeadline(time.Now().Add(kIOInterval))
		n, addr, err := l.lconn.ReadFrom(icmpData[hs+kTunHeaderSize:])
		if err != nil {
			// skip timeout
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				continue
			}

			ctxlog.Errorf(ctx, "client read: %v", err)
			continue
		}
		caddr := addr.(*net.UDPAddr)

		// update client addr
		oaddr := (*net.UDPAddr)(atomic.LoadPointer(&l.pcaddr))
		if oaddr == nil {
			ctxlog.Infof(ctx, "learned client [addr:%v]", caddr)
			atomic.StorePointer(&l.pcaddr, unsafe.Pointer(caddr))
		} else if !(oaddr.IP.Equal(caddr.IP) && oaddr.Port == caddr.Port) {
			ctxlog.Infof(ctx, "client addr update [old:%v] -> [new:%v]", oaddr, caddr)
			atomic.StorePointer(&l.pcaddr, unsafe.Pointer(caddr))
		}

		// pktid
		l.pktid++
		binary.LittleEndian.PutUint32(icmpData[hs+12:hs+16], l.pktid)

		// encode
		encoded := l.Obfuscator.Encode(buf[:ICMPEchoHeaderSize], icmpData[hs:hs+kTunHeaderSize+n])
		if &buf[0] != &encoded[0] {
			panic("should reuse buf")
		}

		// icmp seq
		icmpseq++
		binary.BigEndian.PutUint16(encoded[6:8], icmpseq)
		// checksum
		checksumPut(encoded[2:4], encoded)

		// write icmp req
		_, err = l.icmpconn.WriteTo(encoded, l.raddr)
		if err != nil {
			ctxlog.Errorf(ctx, "reply local error: %v", err)
			continue
		}

		// log
		if l.Verbose {
			ctxlog.Debugf(ctx, "send icmp packet to remote [icmpseq:%v] [pktid:%v] [size:%v/%v]",
				icmpseq, l.pktid, n, len(encoded))
		}
	}

	ctxlog.Debugf(ctx, "stopped read from client")
}

func (l *Local) remote2local(ctx context.Context) {
	ctxlog.Debugf(ctx, "ready to read icmp from remote")

	hs := l.Obfuscator.HeaderSize()
	buf := make([]byte, 128*1024)
	for {
		// test for quit flag
		if l.quiter.IsQuit() {
			break
		}

		// read from remote
		_ = l.icmpconn.SetReadDeadline(time.Now().Add(kIOInterval))
		n, addr, err := l.icmpconn.ReadFrom(buf)
		if err != nil {
			// skip timeout
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				continue
			}

			ctxlog.Errorf(ctx, "remote read: %v", err)
			continue
		}
		ipaddr := addr.(*net.IPAddr)

		if n < ICMPEchoHeaderSize {
			ctxlog.Warnf(ctx, "icmp packet too short, [ip:%v][length:%v]", ipaddr, n)
			continue
		}
		if buf[0] != ICMPTypeEchoReply {
			ctxlog.Debugf(ctx, "not icmp type echo [ip:%v][reply:%v]", ipaddr, buf[0])
			continue
		}
		icmpID := binary.BigEndian.Uint16(buf[4:6])
		icmpSeq := binary.BigEndian.Uint16(buf[6:8])
		icmpData := buf[ICMPEchoHeaderSize:n]

		// decode inplace
		data, err := l.Obfuscator.Decode(icmpData[hs:], icmpData)
		if err != nil {
			ctxlog.Warnf(ctx, "[ip:%v][icmpid:%v][icmpseq:%v] Obfuscator.Decode: %v",
				ipaddr, icmpID, icmpSeq, err)
			continue
		}
		if &icmpData[hs] != &data[0] {
			panic("should reuse buf")
		}

		// src dst cmd pktid
		if len(data) < kTunHeaderSize {
			ctxlog.Errorf(ctx, "[ip:%v][icmpid:%v][icmpseq:%v] short data, length: %v",
				ipaddr, icmpID, icmpSeq, len(data))
			continue
		}
		src := binary.LittleEndian.Uint32(data[0:4])
		dst := binary.LittleEndian.Uint32(data[4:8])
		pktid := binary.LittleEndian.Uint32(data[12:16])
		data = data[kTunHeaderSize:]

		if !(src == l.RemoteID && dst == l.LocalID) {
			ctxlog.Errorf(ctx, "[ip:%v][icmpid:%v][icmpseq:%v] [src:%v][dst:%v] mismatch with [remote:%v][local:%v]",
				ipaddr, icmpID, icmpSeq, src, dst, l.RemoteID, l.LocalID)
			continue
		}

		// log
		if l.Verbose {
			ctxlog.Debugf(ctx, "recv from [remote:%v] [ip:%v][icmpid:%v][icmpseq:%v] [pktid:%v] [size:%v/%v]",
				src, ipaddr, icmpID, icmpSeq, pktid, len(data), n)
		}

		// pktid
		l.bm.Set(pktid)

		// load client addr
		caddr := (*net.UDPAddr)(atomic.LoadPointer(&l.pcaddr))
		if caddr == nil {
			ctxlog.Warnf(ctx, "client addr not learned")
			continue
		}

		// send data to client
		_, err = l.lconn.WriteToUDP(data, caddr)
		if err != nil {
			ctxlog.Errorf(ctx, "write client from [remote:%v]: %v", src, err)
			continue
		}

		// done
	} // for loop

	ctxlog.Debugf(ctx, "stopped to read icmp from remote")
}
