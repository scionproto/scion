// Copyright 2017 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package scion contains socket operations for SCION traffic
package scion

import (
	"net"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"github.com/netsec-ethz/scion/go/lib/sock/reliable"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/util"
)

const (
	RecvBufferSize = 1 << 16
	SendBufferSize = 1 << 16
)

type SCIONNet struct {
	IA             *addr.ISD_AS
	dispatcherPath string
	pm             *PathManager
}

func NewSCIONNet(ia *addr.ISD_AS, sciondPath string, dispatcherPath string) (*SCIONNet, error) {
	var err error
	context := &SCIONNet{IA: ia}
	context.dispatcherPath = dispatcherPath
	context.pm, err = NewPathManager(sciondPath)
	if err != nil {
		return nil, common.NewCError("Unable to initialize PathManager", "err", err)
	}
	return context, nil
}

// DialSCION reserves a UDP port for returning traffic, registers that port
// with the dispatcher, and returns a connection object capable of Read and
// Write calls. Due to how the dispatcher works, the open UDP port will not
// receive SCION traffic and will not process any data. Traffic will instead
// pass through the dispatcher, which sends it to the local application via a
// Reliable (UNIX) socket.
func (c *SCIONNet) DialSCION(IA *addr.ISD_AS, local, remote addr.HostAddr, port uint16) (*SCIONConn, error) {
	// FIXME(scrye): add deadline so Register can time out if the dispatcher is not responding
	regAddr := reliable.AppAddr{Addr: local, Port: 0}
	conn, _, err := reliable.Register(c.dispatcherPath, c.IA, regAddr)
	if err != nil {
		return nil, common.NewCError("Unable to register with dispatcher", "err", err)
	}
	log.Debug("Registered with dispatcher", "ia", c.IA, "addr", regAddr)

	raddr := &SCIONAppAddr{ia: IA, host: remote, port: port}
	laddr := &SCIONAppAddr{ia: c.IA, host: regAddr.Addr, port: regAddr.Port}
	sconn := &SCIONConn{
		Conn:       conn,
		laddr:      laddr,
		raddr:      raddr,
		pm:         c.pm,
		recvBuffer: make(common.RawBytes, RecvBufferSize),
		sendBuffer: make(common.RawBytes, SendBufferSize)}
	return sconn, nil
}

// ListenSCION registers a port with the dispatcher and returns a connection
// object capable of Read and WriteTo calls. ReadFrom and ReadFromSCION can be
// used to get the SCION address which sent the packet.
func (c *SCIONNet) ListenSCION(address addr.HostAddr, port uint16) (*SCIONConn, error) {
	// FIXME(scrye): add deadline so Register can time out if the dispatcher is not responding
	regAddr := reliable.AppAddr{Addr: address, Port: port}
	conn, _, err := reliable.Register(c.dispatcherPath, c.IA, regAddr)
	if err != nil {
		return nil, common.NewCError("Unable to register with dispatcher", "err", err)
	}
	log.Debug("Registered with dispatcher", "ia", c.IA, "addr", regAddr)

	// When we start listening we do not know any paths
	laddr := &SCIONAppAddr{host: address, port: port, ia: c.IA}
	sconn := &SCIONConn{
		Conn:       conn,
		laddr:      laddr,
		pm:         c.pm,
		recvBuffer: make([]byte, RecvBufferSize),
		sendBuffer: make([]byte, SendBufferSize)}
	return sconn, nil
}

type SCIONConn struct {
	*reliable.Conn
	laddr      *SCIONAppAddr
	raddr      *SCIONAppAddr
	pm         *PathManager
	recvBuffer common.RawBytes
	sendBuffer common.RawBytes
}

func (c *SCIONConn) ReadFromSCION(b []byte) (int, *SCIONAppAddr, error) {
	if c.laddr == nil {
		return 0, nil, common.NewCError("Unable to read from uninitialized SCION socket")
	}

	// FIXME(scrye): Cancellation signal to prevent goroutine leaks on block
	_, _, err := c.Conn.ReadFrom(c.recvBuffer)
	if err != nil {
		return 0, nil, common.NewCError("Unable to read from dispatcher", "err", err)
	}

	scnPkt, payload, err := parseSCIONPacket(c.recvBuffer)
	if err != nil {
		return 0, nil, common.NewCError("Unable to parse SCION header", "err", err)
	}
	udpHeader, ok := scnPkt.L4.(*l4.UDP)
	if ok == false {
		return 0, nil, common.NewCError("Unable to parse L4 header", "header", scnPkt.L4)
	}
	// FIXME(scrye): Populate with an empty path for now, since SCION hosts do a path lookup anyway
	sa := &SCIONAppAddr{
		ia:   scnPkt.SrcIA,
		host: scnPkt.SrcHost,
		port: udpHeader.SrcPort,
		path: sciond.PathReplyEntry{}}
	n := copy(b, payload)
	return n, sa, nil
}

func (c *SCIONConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.ReadFromSCION(b)
}

func (c *SCIONConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFromSCION(b)
	return n, err
}

func (c *SCIONConn) WriteToSCION(b []byte, address *SCIONAppAddr) (int, error) {
	if c.laddr == nil {
		return 0, common.NewCError("Unable to write to unitialized SCION socket")
	}
	path, err := c.pm.FindPath(c.laddr.ia, address.ia)
	if err != nil {
		return 0, common.NewCError("Unable to find valid path", "err", err)
	}

	packet, err := c.createUDPPacket(b, address, path)
	if err != nil {
		log.Warn("Error happened", "err", err)
		return 0, err
	}

	var appAddr reliable.AppAddr
	appAddr.Addr = addr.HostFromIP(path.HostInfo.Addrs.Ipv4)
	appAddr.Port = path.HostInfo.Port
	return c.Conn.WriteTo(packet, appAddr)
}

func (c *SCIONConn) WriteTo(b []byte, address net.Addr) (int, error) {
	saddr, ok := address.(*SCIONAppAddr)
	if !ok {
		return 0, common.NewCError("Unable to write (non-SCION address)", "address", address)
	}
	return c.WriteToSCION(b, saddr)
}

func (c *SCIONConn) Write(b []byte) (int, error) {
	if c.raddr == nil {
		return 0, common.NewCError("Unable to write to socket without remote address")
	}
	return c.WriteToSCION(b, c.raddr)
}

func (c *SCIONConn) WriteFoo(b []byte) (int, error) {
	if c.raddr == nil {
		return 0, common.NewCError("Unable to write to socket without remote address")
	}
	return c.WriteToSCION(b, c.raddr)
}

func (c *SCIONConn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *SCIONConn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *SCIONConn) Close() error {
	err := c.Conn.Close()
	if err != nil {
		return common.NewCError("Unable to close reliable socket", "err", err)
	}
	return nil
}

func (c *SCIONConn) createUDPPacket(b []byte, raddr *SCIONAppAddr,
	path sciond.PathReplyEntry) (common.RawBytes, error) {
	// Compute header lengths
	addrHdrLen := raddr.host.Size() + c.laddr.host.Size() + raddr.ia.SizeOf() +
		c.laddr.ia.SizeOf()
	addrHdrLen += util.CalcPadding(addrHdrLen, common.LineLen)
	// We do not include the L4 header size in the total header size
	hdrLen := spkt.CmnHdrLen + addrHdrLen + len(path.Path.FwdPath)
	pktLen := hdrLen + l4.UDPLen + len(b)

	// Prepare forwarding path info
	// Create the packet using initial IF/HF pointers
	_, hopIdx, err := initIndices(path.Path.FwdPath)
	if err != nil {
		return nil, err
	}

	poffset := 0
	// Create Common Header
	commonHeader := c.sendBuffer[:spkt.CmnHdrLen]
	common.Order.PutUint16(commonHeader[:2], (uint16(spkt.SCIONVersion)<<12)+
		(uint16(raddr.host.Type())<<6)+uint16(c.laddr.host.Type()))
	common.Order.PutUint16(commonHeader[2:4], uint16(pktLen))
	commonHeader[4] = uint8(hdrLen) / common.LineLen
	commonHeader[5] = uint8(addrHdrLen+spkt.CmnHdrLen) / common.LineLen
	commonHeader[6] = uint8(addrHdrLen+spkt.CmnHdrLen)/common.LineLen + hopIdx
	commonHeader[7] = uint8(common.L4UDP)
	poffset += spkt.CmnHdrLen

	// Create Address Header
	addrHeader := c.sendBuffer[poffset : poffset+addrHdrLen]
	// Pack the address header
	offset := 0
	raddr.ia.Write(addrHeader[offset:])
	offset += raddr.ia.SizeOf()
	c.laddr.ia.Write(addrHeader[offset:])
	offset += c.laddr.ia.SizeOf()
	copy(addrHeader[offset:], raddr.host.Pack())
	offset += raddr.host.Size()
	copy(addrHeader[offset:], c.laddr.host.Pack())
	offset += c.laddr.host.Size()
	// Zero memory padding because we recycle the buffer
	zeroMemory(addrHeader[offset:])
	poffset += addrHdrLen

	// Copy Forwarding Path
	copy(c.sendBuffer[poffset:], path.Path.FwdPath)
	poffset += len(path.Path.FwdPath)

	// Create SCION/UDP Header
	udpHeader := c.sendBuffer[poffset : poffset+l4.UDPLen]
	common.Order.PutUint16(udpHeader[:2], c.laddr.port)
	common.Order.PutUint16(udpHeader[2:4], raddr.port)
	common.Order.PutUint16(udpHeader[4:6], uint16(len(b))+l4.UDPLen)
	common.Order.PutUint16(udpHeader[6:8], util.Checksum(addrHeader,
		[]byte{0, commonHeader[7]}, udpHeader[:6], b))
	poffset += l4.UDPLen

	// Copy payload
	copy(c.sendBuffer[poffset:], b)
	poffset += len(b)

	return c.sendBuffer[:poffset], nil
}

func zeroMemory(b common.RawBytes) {
	for i := 0; i < len(b); i++ {
		b[i] = 0
	}
}

// ScnPktFromRaw parses an in-memory raw packet, useful when SCION packets are transported
// via a lower-layer framing protocol (e.g., ReliableSocket). The returned payload is _not_
// a copy, it is a slice which points to the payload in buf.
func parseSCIONPacket(buf common.RawBytes) (*spkt.ScnPkt, []byte, error) {
	offset := uint16(0)
	scnPkt := new(spkt.ScnPkt)
	var err error

	scnPkt.CmnHdr, err = spkt.CmnHdrFromRaw(buf[:8])
	if err != nil {
		return nil, nil, err
	}
	offset += 8

	scnPkt.DstIA = addr.IAFromRaw(buf[offset : offset+addr.IABytes])
	offset += addr.IABytes

	scnPkt.SrcIA = addr.IAFromRaw(buf[offset : offset+addr.IABytes])
	offset += addr.IABytes

	scnPkt.DstHost, err = addr.HostFromRaw(buf[offset:], scnPkt.CmnHdr.DstType)
	if err != nil {
		return nil, nil, err
	}
	dstLen, err := addr.HostLen(scnPkt.CmnHdr.DstType)
	if err != nil {
		return nil, nil, err
	}
	offset += uint16(dstLen)

	scnPkt.SrcHost, err = addr.HostFromRaw(buf[offset:], scnPkt.CmnHdr.SrcType)
	if err != nil {
		return nil, nil, err
	}
	srcLen, err := addr.HostLen(scnPkt.CmnHdr.SrcType)
	if err != nil {
		return nil, nil, err
	}
	offset += uint16(srcLen)

	// Skip padding, NB: SCION states addr.HostLenIPv6 is largest accepted address size
	if dstLen > addr.HostLenIPv6 {
		return nil, nil, common.NewCError("Address too large", "dstLen", dstLen)
	}
	if srcLen > addr.HostLenIPv6 {
		return nil, nil, common.NewCError("Address too large", "srcLen", srcLen)
	}
	addrPadLen := uint8((2*addr.HostLenIPv6 - dstLen - srcLen) % 8)
	offset += uint16(addrPadLen)

	addrHeaderLen := addrPadLen + srcLen + dstLen + 2*addr.IABytes

	// Compute forwarding path length, lengths are in the last byte of the 8-byte InfoField
	//pathLength := uint16(0)
	pathLength := uint16(scnPkt.CmnHdr.HdrLen*common.LineLen) - uint16(spkt.CmnHdrLen) - uint16(addrHeaderLen)
	offset += pathLength

	scnPkt.Path = new(spath.Path)
	scnPkt.Path.Raw = make(common.RawBytes, pathLength)
	copy(scnPkt.Path.Raw, buf[offset-pathLength:offset])
	scnPkt.Path.InfOff = int(scnPkt.CmnHdr.CurrInfoF) * common.LineLen
	scnPkt.Path.HopOff = int(scnPkt.CmnHdr.CurrHopF) * common.LineLen

	// Jump directly after header
	offset = uint16(scnPkt.CmnHdr.HdrLen * common.LineLen)

	// Only unpack UDP for now
	if scnPkt.CmnHdr.NextHdr != common.L4UDP {
		return nil, nil, common.NewCError("Unsupported L4 protocol", "proto", scnPkt.CmnHdr.NextHdr)
	}
	scnPkt.L4, err = l4.UDPFromRaw(buf[offset : offset+l4.UDPLen])
	if err != nil {
		return nil, nil, err
	}
	offset += l4.UDPLen

	payloadLength := scnPkt.CmnHdr.TotalLen - uint16(scnPkt.CmnHdr.HdrLen*common.LineLen) - l4.UDPLen

	return scnPkt, buf[offset : offset+payloadLength], nil
}

func initIndices(fwdPath common.RawBytes) (infoIdx, hopIdx uint8, err error) {
	infoIdx, hopIdx = 0, 1

	info, ierr := spath.InfoFFromRaw(fwdPath[infoIdx*8 : infoIdx*8+8])
	if ierr != nil {
		return 0, 0, ierr
	}
	maxHopIdx := info.Hops

	hop, ierr := spath.HopFFromRaw(fwdPath[hopIdx*8 : hopIdx*8+8])
	if ierr != nil {
		return 0, 0, ierr
	}

	if info.Up && hop.Xover {
		hopIdx += 1
		if hopIdx > maxHopIdx {
			return 0, 0, common.NewCError("Skipped entire path segment", "hopIdx", hopIdx,
				"maxHopIdx", maxHopIdx)
		}
	}

	for {
		hop, ierr = spath.HopFFromRaw(fwdPath[hopIdx*8 : hopIdx*8+8])
		if ierr != nil {
			return 0, 0, ierr
		}

		if hop.VerifyOnly {
			hopIdx += 1
			if hopIdx > maxHopIdx {
				return 0, 0, common.NewCError("Skipped entire path segment", "hopIdx", hopIdx,
					"maxHopIdx", maxHopIdx)
			}
		} else {
			break
		}
	}

	return infoIdx, hopIdx, nil
}
