package scion

import (
	"encoding/binary"
	"net"

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

type SCIONConn struct {
	*reliable.Conn

	srcIA    *addr.ISD_AS
	dstIA    *addr.ISD_AS
	srcLocal addr.HostAddr
	dstLocal addr.HostAddr
	srcPort  uint16
	dstPort  uint16
	path     sciond.PathReplyEntry
}

func New(dispatcher *reliable.Conn, srcIA *addr.ISD_AS, srcLocal addr.HostAddr, srcPort uint16,
	dstIA *addr.ISD_AS, dstLocal addr.HostAddr, dstPort uint16,
	path sciond.PathReplyEntry) (*SCIONConn, error) {
	conn := &SCIONConn{
		Conn:     dispatcher,
		srcIA:    srcIA,
		srcLocal: srcLocal,
		srcPort:  srcPort,
		dstIA:    dstIA,
		dstLocal: dstLocal,
		dstPort:  dstPort,
		path:     path,
	}
	return conn, nil
}

func (c *SCIONConn) SetPathPolicy() error {
	return common.NewError("Not implemented.", "func", "SetPathPolicy")
}

func (c *SCIONConn) Read(b []byte) (int, error) {
	_, err := c.Conn.Read(b)
	if err != nil {
		return 0, common.NewError("Unable to read from SCION conn", "err", err)
	}

	aux := make([]byte, len(b), cap(b))
	packet, _, err := ParseSCIONPacket(aux)
	if err != nil {
		return 0, common.NewError("Unable to parse SCION packet", "err", err)
	}

	log.Debug("Packet", "packet", packet)
	log.Debug("Payload", "packet.Pld", packet.Pld)
	n, cerr := packet.Pld.Write(b)
	if cerr != nil {
		return 0, common.NewError("Unable to write payload", "cerr", cerr)
	}

	return n, nil
}

func (c *SCIONConn) Write(b []byte) (int, error) {
	packet, err := c.createUDPPacket(b)
	if err != nil {
		return 0, err
	}

	// TODO(scrye): change from ephemeral UDP sockets to persistent ones
	var addr net.UDPAddr
	addr.IP = c.path.HostInfo.Addrs.Ipv4
	addr.Port = int(c.path.HostInfo.Port)
	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		return 0, err
	}

	n, err := conn.Write(packet)
	conn.Close()
	return n, err
}

func (c *SCIONConn) Close() error {
	return nil
}

func (c *SCIONConn) createUDPPacket(b []byte) (common.RawBytes, error) {
	// SCION Version 0 common headers are 8-byte long
	commonHeaderSize := 8
	commonHeader := make([]byte, commonHeaderSize)
	commonHeader[0] |= (uint8(c.dstLocal.Type()) >> 2) << 4
	commonHeader[1] |= uint8(c.dstLocal.Type()) << 6
	commonHeader[1] |= uint8(c.srcLocal.Type())

	addrHeaderSize := c.dstLocal.Size() + c.srcLocal.Size() + c.dstIA.SizeOf() + c.srcIA.SizeOf()
	addrHeader := make([]byte, addrHeaderSize)
	// Pad to multiple of LineLen, 40 is max address header as defined by SCION specification
	if addrHeaderSize > 40 {
		return nil, common.NewError("Invalid address header size", "size", addrHeaderSize)
	}
	addrHeaderSize += (40 - addrHeaderSize) % 8

	// We do not include the L4 header size in the total header size
	totalHeaderSize := commonHeaderSize + addrHeaderSize + len(c.path.Path.FwdPath)
	totalPacketSize := totalHeaderSize + l4.UDPLen + len(b)

	binary.BigEndian.PutUint16(commonHeader[2:4], uint16(totalPacketSize))
	commonHeader[4] = uint8(totalHeaderSize) / common.LineLen

	// Create the packet using initial IF/HF pointers
	_, hopIdx, err := InitIndices(c.path.Path.FwdPath)
	if err != nil {
		return nil, err
	}

	commonHeader[5] = uint8(addrHeaderSize+commonHeaderSize) / common.LineLen
	commonHeader[6] = uint8(addrHeaderSize+commonHeaderSize)/common.LineLen + hopIdx
	commonHeader[7] = uint8(common.L4UDP)

	// Pack the address header
	offset := 0
	c.dstIA.Write(addrHeader[offset : offset+c.dstIA.SizeOf()])
	offset += c.dstIA.SizeOf()
	c.srcIA.Write(addrHeader[offset : offset+c.srcIA.SizeOf()])
	offset += c.srcIA.SizeOf()
	copy(addrHeader[offset:offset+c.dstLocal.Size()], c.dstLocal.Pack())
	offset += c.dstLocal.Size()
	copy(addrHeader[offset:offset+c.srcLocal.Size()], c.srcLocal.Pack())
	// And the padding, if it exists, contains leftover zeroes

	// Pack the L4 header
	// TODO(scrye): Might want to refactor L4 stuff out of lib/common?
	udpHeader := make([]byte, l4.UDPLen)

	binary.BigEndian.PutUint16(udpHeader[0:2], c.srcPort)
	binary.BigEndian.PutUint16(udpHeader[2:4], c.dstPort)
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(len(b))+l4.UDPLen)

	// Compute the checksum for SCION L4
	// NOTE(scrye): is the checksum supposed to be this way? it breaks stack encap/decap
	// principles (encapsulated UDP protocol looks at bytes from upper layer SCION protocol)
	binary.BigEndian.PutUint16(udpHeader[6:8], libscion.Checksum(addrHeader[0:16],
		commonHeader[7:8], udpHeader, b))

	packet := make([]byte, 0)
	packet = append(packet, commonHeader...)
	packet = append(packet, addrHeader...)
	packet = append(packet, c.path.Path.FwdPath...)
	packet = append(packet, udpHeader...)
	packet = append(packet, b...)

	return packet, nil
}

// ScnPktFromRaw parses an in-memory raw packet, useful when SCION packets are transported
// via a lower-layer framing protocol (e.g., ReliableSocket)
func ParseSCIONPacket(buf common.RawBytes) (*spkt.ScnPkt, []byte, error) {
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

	// Make a pristine copy of the payload field, in case applications toy around with it
	// TODO(scrye): validate buffer length
	payloadLength := scnPkt.CmnHdr.TotalLen - uint16(scnPkt.CmnHdr.HdrLen*common.LineLen) - l4.UDPLen

	return scnPkt, buf[offset : offset+payloadLength], nil
}

// RawPayload implements interface common.Payload for byte slices
type RawPayload common.RawBytes

func (pld RawPayload) String() string {
	return common.RawBytes(pld).String()
}

func (pld RawPayload) Len() int {
	return len(pld)
}

func (pld RawPayload) Copy() (common.Payload, *common.Error) {
	newPld := make(RawPayload, pld.Len())
	copy(newPld, pld)

	return newPld, nil
}

func (pld RawPayload) Write(b common.RawBytes) (int, *common.Error) {
	return copy(pld, b), nil
}

func InitIndices(fwdPath common.RawBytes) (infoIdx, hopIdx uint8, err error) {
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
