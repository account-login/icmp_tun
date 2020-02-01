package icmp_tun

import (
	"context"
	"encoding/binary"
	"github.com/pkg/errors"
	"golang.org/x/net/icmp"
	"gopkg.in/account-login/ctxlog.v2"
	"net"
	"sync"
	"time"
)

// TODO: expire idle peer

type Remote struct {
	Target     string
	NodeId     uint32
	Verbose    bool
	EnableEcho bool
	Obfuscator Obfuscator
	// states
	taddr    *net.UDPAddr
	icmpconn *icmp.PacketConn
	mu       sync.Mutex
	id2peer  map[uint32]*localPeer
	quiter   Quiter
}

type localPeer struct {
	r       *Remote
	id      uint32
	mu      sync.Mutex
	ipaddr  *net.IPAddr
	icmpid  uint16
	icmpseq uint16
	lconn   *net.UDPConn
	pktid   uint32
	st      Stats
}

func (r *Remote) Run(ctx context.Context) error {
	if r.NodeId == 0 || r.Obfuscator == nil {
		return errors.New("r.NodeId == 0 || r.Obfuscator == nil")
	}

	// resolve target addr
	var err error
	r.taddr, err = net.ResolveUDPAddr("udp", r.Target)
	if err != nil {
		return errors.Wrap(err, "resolve target")
	}
	ctxlog.Debugf(ctx, "target resolved: %v", r.taddr)

	// ICMP Conn
	r.icmpconn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return errors.Wrap(err, "listen for local")
	}
	defer SafeClose(ctx, r.icmpconn)

	// init states
	r.id2peer = map[uint32]*localPeer{}
	r.quiter.Init()

	// convert ctx.Done() to quit flag
	go func() {
		<-ctx.Done()
		r.quiter.Quit()
	}()

	// process local input
	r.local2remote(ctx)

	// done
	return ctx.Err()
}

func (r *Remote) local2remote(ctx context.Context) {
	ctxlog.Debugf(ctx, "ready to read icmp from local")

	hs := r.Obfuscator.HeaderSize()
	buf := make([]byte, 128*1024)
	for {
		// test for quit flag
		if r.quiter.IsQuit() {
			break
		}

		// read from local
		_ = r.icmpconn.SetReadDeadline(time.Now().Add(kIOInterval))
		n, addr, err := r.icmpconn.ReadFrom(buf)
		if err != nil {
			// skip timeout
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				continue
			}

			ctxlog.Errorf(ctx, "local read: %v", err)
			continue
		}
		ipaddr := addr.(*net.IPAddr)

		/*
			https://tools.ietf.org/html/rfc792
			Echo or Echo Reply Message
			    0                   1                   2                   3
			    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   |     Type      |     Code      |          Checksum             |
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   |           Identifier          |        Sequence Number        |
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   |     Data ...
		*/
		if n < ICMPEchoHeaderSize+hs {
			ctxlog.Warnf(ctx, "icmp packet from [ip:%v] too short, length: %v", ipaddr, n)
			continue
		}
		if buf[0] != ICMPTypeEcho {
			ctxlog.Debugf(ctx, "[ip:%v] not icmp type echo: %v", ipaddr, buf[0])
			continue
		}
		icmpID := binary.BigEndian.Uint16(buf[4:6])
		icmpSeq := binary.BigEndian.Uint16(buf[6:8])
		icmpData := buf[ICMPEchoHeaderSize:n]

		// decode inplace
		data, err := r.Obfuscator.Decode(icmpData[hs:], icmpData)
		if err != nil {
			if r.EnableEcho {
				// reply normal ping
				buf[0] = ICMPTypeEchoReply
				// update checksum
				checksumUpdate(buf[2:4], ICMPTypeEcho, ICMPTypeEchoReply)
				// reply echo
				_, err = r.icmpconn.WriteTo(buf[:n], ipaddr)
				if err != nil {
					ctxlog.Errorf(ctx, "[ip:%v][icmpid:%v][icmpseq:%v] icmp echo reply: %v",
						ipaddr, icmpID, icmpSeq, err)
					continue
				}

				ctxlog.Debugf(ctx, "icmp echo reply to [ip:%v][icmpid:%v][icmpseq:%v] [size:%v]",
					ipaddr, icmpID, icmpSeq, n)
			} else {
				ctxlog.Warnf(ctx, "[ip:%v][icmpid:%v][icmpseq:%v] Obfuscator.Decode: %v",
					ipaddr, icmpID, icmpSeq, err)
			}
			continue
		}
		if &icmpData[hs] != &data[0] {
			panic("should reuse buf")
		}

		// src dst cmd pktid
		if len(data) < kTunHeaderSize {
			ctxlog.Errorf(ctx, "short data, length: %v", len(data))
			continue
		}
		src := binary.LittleEndian.Uint32(data[0:4])
		dst := binary.LittleEndian.Uint32(data[4:8])
		pktid := binary.LittleEndian.Uint32(data[12:16])
		data = data[kTunHeaderSize:]

		if dst != r.NodeId {
			ctxlog.Errorf(ctx, "[dst:%v] != [myid:%v] [src:%v][ip:%v]",
				dst, r.NodeId, src, ipaddr)
			continue
		}

		// update or create peer
		peer := r.updatePeer(ctx, ipaddr, icmpID, icmpSeq, src, pktid)
		if peer == nil {
			continue
		}

		// log
		if r.Verbose {
			ctxlog.Debugf(ctx, "recv from [local:%v] [ip:%v][icmpid:%v][icmpseq:%v] [pktid:%v] [size:%v/%v]",
				src, ipaddr, icmpID, icmpSeq, pktid, len(data), n)
		}

		// stats
		if peer.st.Update(pktid) {
			ctxlog.Infof(ctx, "[local:%v] loss count: [%v/%v] [%v/%v] [%v/%v]",
				src,
				peer.st.Loss100, peer.st.Count100,
				peer.st.Loss1000, peer.st.Count1000,
				peer.st.Loss10000, peer.st.Count10000,
			)
		}

		// send data to target
		// NOTE: race with r.delPeer()
		_, err = peer.lconn.WriteToUDP(data, r.taddr)
		if err != nil {
			ctxlog.Errorf(ctx, "write target for [local:%v]: %v", src, err)
			continue
		}

		// done
	} // for loop

	// clean up
	r.quiter.Wait()
	if len(r.id2peer) != 0 {
		panic("len(r.id2peer) != 0")
	}
}

func (r *Remote) getPeer(id uint32) *localPeer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.id2peer[id]
}

func (r *Remote) updatePeer(
	ctx context.Context, ipaddr *net.IPAddr,
	icmpID uint16, icmpSeq uint16, id uint32, pktid uint32) *localPeer {
	// body
	ctx = ctxlog.Pushf(ctx, "[local:%v]", id)

	r.mu.Lock()
	defer r.mu.Unlock()

	peer, ok := r.id2peer[id]
	if !ok {
		// new peer
		ctxlog.Infof(ctx, "ip:id learned: %v:%v", ipaddr, icmpID)
		peer = &localPeer{
			r: r, id: id, ipaddr: ipaddr, icmpid: icmpID, icmpseq: icmpSeq,
			pktid: uint32(Rand64ByTime()),
		}
		peer.st.Init()

		var err error
		peer.lconn, err = net.ListenUDP("udp4", nil)
		if err != nil {
			ctxlog.Errorf(ctx, "can not listen udp for local: %v", err)
			return nil
		}
		ctxlog.Infof(ctx, "listen on [addr:%v] for target", peer.lconn.LocalAddr())

		// start target reader
		if !r.quiter.Go(func() { peer.target2remote(ctx) }) {
			ctxlog.Debugf(ctx, "quiting, can not start target reader")
			SafeClose(ctx, peer.lconn)
			return nil
		}

		// ok
		r.id2peer[id] = peer
	} else {
		peer.mu.Lock()
		defer peer.mu.Unlock()

		if !(peer.ipaddr.IP.Equal(ipaddr.IP) && peer.icmpid == icmpID) {
			// update local ip
			ctxlog.Infof(ctx, "local ip:id updated [old:%v:%v] -> [new:%v:%v]",
				peer.ipaddr, peer.icmpid, ipaddr, icmpID)
			peer.ipaddr = ipaddr
			peer.icmpid = icmpID
		}
		peer.icmpseq = icmpSeq
	}

	return peer
}

func (r *Remote) delPeer(ctx context.Context, id uint32) {
	r.mu.Lock()
	p := r.id2peer[id]
	delete(r.id2peer, id)
	r.mu.Unlock()
	SafeClose(ctx, p.lconn)
}

func (p *localPeer) target2remote(ctx context.Context) {
	ctxlog.Debugf(ctx, "ready to read from target for local")

	// clean up
	defer p.r.delPeer(ctx, p.id)

	//   1B |   1B |     2B | 2B |  2B | 8B |  4B |  4B |  4B |    4B |
	// type | code | chksum | id | seq | HS | src | dst | cmd | pktid | data
	// -------------------------------
	//        ICMP ECHO HEADER
	hs := p.r.Obfuscator.HeaderSize()
	buf := make([]byte, 128*1024)
	buf[0] = ICMPTypeEchoReply
	buf[1] = 0
	icmpData := buf[ICMPEchoHeaderSize:]

	for {
		// test for quit flag
		if p.r.quiter.IsQuit() {
			break
		}

		// src dst cmd
		binary.LittleEndian.PutUint32(icmpData[hs+0:hs+4], p.r.NodeId)
		binary.LittleEndian.PutUint32(icmpData[hs+4:hs+8], p.id)
		binary.LittleEndian.PutUint32(icmpData[hs+8:hs+12], 0)

		// read from local
		_ = p.lconn.SetReadDeadline(time.Now().Add(kIOInterval))
		n, addr, err := p.lconn.ReadFrom(icmpData[hs+kTunHeaderSize:])
		if err != nil {
			// skip timeout
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				continue
			}

			ctxlog.Errorf(ctx, "target read: %v", err)
			continue
		}
		taddr := addr.(*net.UDPAddr)

		// verify target addr
		if !(taddr.IP.Equal(p.r.taddr.IP) && taddr.Port == p.r.taddr.Port) {
			ctxlog.Warnf(ctx, "drop from [non-target:%v] [pktlen:%v]", taddr, n)
			continue
		}

		// pktid
		p.pktid++
		binary.LittleEndian.PutUint32(icmpData[hs+12:hs+16], p.pktid)

		// encode
		encoded := p.r.Obfuscator.Encode(buf[:ICMPEchoHeaderSize], icmpData[hs:hs+kTunHeaderSize+n])
		if &buf[0] != &encoded[0] {
			panic("should reuse buf")
		}

		// read local ip and icmp id
		p.mu.Lock()
		ipaddr := p.ipaddr
		icmpid := p.icmpid
		icmpseq := p.icmpseq
		p.mu.Unlock()

		// icmp id, icmp seq
		binary.BigEndian.PutUint16(encoded[4:6], icmpid)
		binary.BigEndian.PutUint16(encoded[6:8], icmpseq)
		// checksum
		checksumPut(encoded[2:4], encoded)

		// write icmp reply
		_, err = p.r.icmpconn.WriteTo(encoded, ipaddr)
		if err != nil {
			ctxlog.Errorf(ctx, "reply local error: %v", err)
			continue
		}

		// log
		if p.r.Verbose {
			ctxlog.Debugf(ctx, "reply icmp packet to local [pktid:%v] [size:%v/%v]",
				p.pktid, n, len(encoded))
		}
	} // for loop
}
