// Package scion contains socket operations for SCION traffic
package scion

import (
	"encoding/binary"
	"net"
	"sync"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/libscion"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"github.com/netsec-ethz/scion/go/lib/sock/reliable"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/spkt"
)

const (
	RecvBufferSize = 1500
)

type Context struct {
	IA             *addr.ISD_AS
	dispatcherPath string
	pm             *PathManager
}

func NewContext(ia *addr.ISD_AS, sciondPath string, dispatcherPath string) (*Context, error) {
	var err error
	context := &Context{IA: ia}
	context.dispatcherPath = dispatcherPath
	context.pm, err = NewPathManager(context, sciondPath)
	if err != nil {
		return nil, common.NewError("Unable to initialize PathManager", "err", err)
	}
	return context, nil
}

type SCIONConn struct {
	*reliable.Conn
	udpConn    *net.UDPConn
	laddr      *SCIONAddr
	raddr      *SCIONAddr
	pm         *PathManager
	recvBuffer []byte
	lock       sync.Mutex
}

// DialSCION reserves a UDP port for returning traffic, registers that port
// with the dispatcher, and returns a connection object capable of Read and
// Write calls. Due to how the dispatcher works, the open UDP port will not
// receive SCION traffic and will not process any data. Traffic will instead
// pass through the dispatcher, which sends it to the local application via a
// Reliable (UNIX) socket.
func (c *Context) DialSCION(IA *addr.ISD_AS, address addr.HostAddr, port uint16) (*SCIONConn, error) {
	// Reserve local addr and port for returning traffic.
	udpConn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, common.NewError("Unable to assign port", "err", err)
	}

	local := udpConn.LocalAddr()
	udpLocalAddr, err := net.ResolveUDPAddr(local.Network(), local.String())
	if err != nil {
		return nil, common.NewError("Unable to extract UDP address", "err", err)
	}

	// FIXME(scrye): add deadline so Register can time out if the dispatcher is not responding
	regAddr := reliable.AppAddr{Addr: addr.HostFromIP(udpLocalAddr.IP), Port: uint16(udpLocalAddr.Port)}
	conn, _, err := reliable.Register(c.dispatcherPath, c.IA, regAddr)
	if err != nil {
		return nil, common.NewError("Unable to register with dispatcher", "err", err)
	}
	log.Debug("Registered with dispatcher", "ia", c.IA, "addr", regAddr)

	raddr := &SCIONAddr{ia: IA, host: address, port: port}
	laddr := &SCIONAddr{ia: c.IA, host: regAddr.Addr, port: regAddr.Port}
	sconn := &SCIONConn{
		Conn:       conn,
		laddr:      laddr,
		raddr:      raddr,
		udpConn:    udpConn,
		pm:         c.pm,
		recvBuffer: make([]byte, RecvBufferSize)}
	return sconn, nil
}

// ListenSCION registers a port with the dispatcher and returns a connection
// object capable of Read and WriteTo calls. ReadFrom and ReadFromSCION can be
// used to get the SCION address which sent the packet.
func (c *Context) ListenSCION(address addr.HostAddr, port uint16) (*SCIONConn, error) {
	// Open up local UDP port for sending traffic
	udpAddr := &net.UDPAddr{IP: address.IP(), Port: int(port)}
	udpConn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, common.NewError("Unable to reserver UDP port for SCION listen", "addr", address,
			"port", port)
	}

	// FIXME(scrye): add deadline so Register can time out if the dispatcher is not responding
	regAddr := reliable.AppAddr{Addr: address, Port: port}
	conn, _, err := reliable.Register(c.dispatcherPath, c.IA, regAddr)
	if err != nil {
		return nil, common.NewError("Unable to register with dispatcher", "err", err)
	}
	log.Debug("Registered with dispatcher", "ia", c.IA, "addr", regAddr)

	// When we start listening we do not know any paths
	laddr := &SCIONAddr{host: address, port: port, ia: c.IA}
	sconn := &SCIONConn{
		Conn:       conn,
		laddr:      laddr,
		udpConn:    udpConn,
		pm:         c.pm,
		recvBuffer: make([]byte, RecvBufferSize)}
	return sconn, nil
}

func (c *SCIONConn) ReadFromSCION(b []byte) (int, *SCIONAddr, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.laddr == nil {
		return 0, nil, common.NewError("Unable to read from uninitialized SCION socket")
	}

	// FIXME(scrye): Cancellation signal to prevent goroutine leaks on block
	_, _, err := c.Conn.ReadFrom(c.recvBuffer)
	if err != nil {
		return 0, nil, common.NewError("Unable to read from dispatcher", "err", err)
	}

	scnPkt, payload, err := parseSCIONPacket(c.recvBuffer)
	if err != nil {
		return 0, nil, common.NewError("Unable to parse SCION header", "err", err)
	}
	udpHeader, ok := scnPkt.L4.(*l4.UDP)
	if ok == false {
		return 0, nil, common.NewError("Unable to parse L4 header", "header", scnPkt.L4)
	}
	// FIXME(scrye): Populate with an empty path for now, since SCION hosts do a path lookup anyway
	sa := &SCIONAddr{
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

func (c *SCIONConn) WriteToSCION(b []byte, address *SCIONAddr) (int, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.laddr == nil {
		return 0, common.NewError("Unable to write to unitialized SCION socket")
	}
	path, err := c.pm.FindPath(c.laddr.ia, address.ia)
	if err != nil {
		return 0, common.NewError("Unable to find valid path", "err", err)
	}

	packet, err := c.createUDPPacket(b, address, path)
	if err != nil {
		return 0, err
	}

	// FIXME(scrye): change from ephemeral UDP sockets to reusable ones
	var addr net.UDPAddr
	addr.IP = path.HostInfo.Addrs.Ipv4
	addr.Port = int(path.HostInfo.Port)
	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		return 0, err
	}

	return conn.Write(packet)
}

func (c *SCIONConn) WriteTo(b []byte, address net.Addr) (int, error) {
	saddr, ok := address.(*SCIONAddr)
	if !ok {
		return 0, common.NewError("Unable to write (non-SCION address)", "address", address)
	}
	return c.WriteToSCION(b, saddr)
}

func (c *SCIONConn) Write(b []byte) (int, error) {
	if c.raddr == nil {
		return 0, common.NewError("Unable to write to socket without remote address")
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
	c.lock.Lock()
	defer c.lock.Unlock()

	err := c.Conn.Close()
	if err != nil {
		return common.NewError("Unable to close reliable socket", "err", err)
	}
	if c.udpConn != nil {
		err := c.udpConn.Close()
		if err != nil {
			return common.NewError("Unable to close UDP socket", "err", err)
		}
	}
	return nil
}

// createUDPPacket encapsulates a payload with a L4 UDP header and a L3 SCION header
func (c *SCIONConn) createUDPPacket(b []byte, raddr *SCIONAddr, path sciond.PathReplyEntry) (common.RawBytes, error) {
	// SCION Version 0 common headers are 8-byte long
	commonHeaderSize := 8
	commonHeader := make([]byte, commonHeaderSize)
	commonHeader[0] |= (uint8(raddr.host.Type()) >> 2) << 4
	commonHeader[1] |= uint8(raddr.host.Type()) << 6
	commonHeader[1] |= uint8(c.laddr.host.Type())

	addrHeaderSize := raddr.host.Size() + c.laddr.host.Size() + raddr.ia.SizeOf() + c.laddr.ia.SizeOf()
	addrHeader := make([]byte, addrHeaderSize)
	// Pad to multiple of LineLen, 40 is max address header as defined by SCION specification
	if addrHeaderSize > 40 {
		return nil, common.NewError("Invalid address header size", "size", addrHeaderSize)
	}
	addrHeaderSize += (40 - addrHeaderSize) % 8

	// We do not include the L4 header size in the total header size
	totalHeaderSize := commonHeaderSize + addrHeaderSize + len(path.Path.FwdPath)
	totalPacketSize := totalHeaderSize + l4.UDPLen + len(b)

	binary.BigEndian.PutUint16(commonHeader[2:4], uint16(totalPacketSize))
	commonHeader[4] = uint8(totalHeaderSize) / common.LineLen

	// Create the packet using initial IF/HF pointers
	_, hopIdx, err := initIndices(path.Path.FwdPath)
	if err != nil {
		return nil, err
	}

	commonHeader[5] = uint8(addrHeaderSize+commonHeaderSize) / common.LineLen
	commonHeader[6] = uint8(addrHeaderSize+commonHeaderSize)/common.LineLen + hopIdx
	commonHeader[7] = uint8(common.L4UDP)

	// Pack the address header
	offset := 0
	raddr.ia.Write(addrHeader[offset : offset+raddr.ia.SizeOf()])
	offset += raddr.ia.SizeOf()
	c.laddr.ia.Write(addrHeader[offset : offset+c.laddr.ia.SizeOf()])
	offset += c.laddr.ia.SizeOf()
	copy(addrHeader[offset:offset+raddr.host.Size()], raddr.host.Pack())
	offset += raddr.host.Size()
	copy(addrHeader[offset:offset+c.laddr.host.Size()], c.laddr.host.Pack())
	// And the padding, if it exists, contains leftover zeroes

	// Pack the L4 header
	// TODO(scrye): Might want to refactor L4 stuff out of lib/common?
	udpHeader := make([]byte, l4.UDPLen)

	binary.BigEndian.PutUint16(udpHeader[0:2], c.laddr.port)
	binary.BigEndian.PutUint16(udpHeader[2:4], raddr.port)
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(len(b))+l4.UDPLen)

	// Compute the checksum for SCION L4
	// NOTE(scrye): is the checksum supposed to be this way? it breaks stack encap/decap
	// principles (encapsulated UDP protocol looks at bytes from upper layer SCION protocol)
	binary.BigEndian.PutUint16(udpHeader[6:8], libscion.Checksum(addrHeader[0:16],
		commonHeader[7:8], udpHeader, b))

	packet := make([]byte, 0)
	packet = append(packet, commonHeader...)
	packet = append(packet, addrHeader...)
	packet = append(packet, path.Path.FwdPath...)
	packet = append(packet, udpHeader...)
	packet = append(packet, b...)

	return packet, nil
}

// ScnPktFromRaw parses an in-memory raw packet, useful when SCION packets are transported
// via a lower-layer framing protocol (e.g., ReliableSocket). The returned payload is _not_
// a copy, it is a slice which points to the payload in buf.
func parseSCIONPacket(buf common.RawBytes) (*spkt.ScnPkt, []byte, error) {
	offset := uint16(0)
	scnPkt := new(spkt.ScnPkt)
	// TODO(scrye): err is defined here to avoid nil interface issues
	var err *common.Error

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
		return nil, nil, common.NewError("Address too large", "dstLen", dstLen)
	}
	if srcLen > addr.HostLenIPv6 {
		return nil, nil, common.NewError("Address too large", "srcLen", srcLen)
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
		return nil, nil, common.NewError("Unsupported L4 protocol", "proto", scnPkt.CmnHdr.NextHdr)
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
			return 0, 0, common.NewError("Skipped entire path segment", "hopIdx", hopIdx,
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
				return 0, 0, common.NewError("Skipped entire path segment", "hopIdx", hopIdx,
					"maxHopIdx", maxHopIdx)
			}
		} else {
			break
		}
	}

	return infoIdx, hopIdx, nil
}
