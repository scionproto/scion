package main

import (
	"fmt"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spkt"
)

func newSCMPPkt(t scmp.Type, info scmp.Info, ext common.Extension) *spkt.ScnPkt {
	var exts []common.Extension
	scmpMeta := scmp.Meta{InfoLen: uint8(info.Len())}
	pld := make(common.RawBytes, scmp.MetaLen+info.Len())
	scmpMeta.Write(pld)
	info.Write(pld[scmp.MetaLen:])
	scmpHdr := scmp.NewHdr(scmp.ClassType{Class: scmp.C_General, Type: t}, len(pld))
	if ext != nil {
		exts = []common.Extension{ext}
	}

	pkt := &spkt.ScnPkt{
		DstIA:   remote.IA,
		SrcIA:   local.IA,
		DstHost: remote.Host,
		SrcHost: local.Host,
		Path:    remote.Path,
		HBHExt:  exts,
		L4:      scmpHdr,
		Pld:     pld,
	}
	return pkt
}

// scmpCtx is used to maintain some context information used by the application
type scmpCtx struct {
	// pktS is the scion packet to send
	pktS *spkt.ScnPkt
	// pktR is the received scion packet
	pktR *spkt.ScnPkt
	// ctS is the SCMP class and type of the packets to send
	ctS scmp.ClassType
	// ctR is the expected SCMP class and type of the received packets
	ctR scmp.ClassType
	// infoS is the Info part of the SCMP payload, that it updates per packet sent
	infoS scmp.Info
	// InfoR is the Info part of the received SCMP packet payload, used for
	// validation and pretty printing
	infoR scmp.Info
	// total is the total number of packets to send (0 means unlimited)
	total uint64
	// sent is the number of sent packets
	sent uint64
	// recv is the number of received packets
	recv uint64
}

func initSCMP(ctx *scmpCtx, typeStr string, total uint, pathEntry *sciond.PathReplyEntry) {
	switch {
	case typeStr == "echo":
		initEcho(ctx, total)
	case typeStr == "rp" || typeStr == "recordpath":
		initRecordPath(ctx, pathEntry)
	default:
		fatal("Invalid SCMP type")
	}
}

func initEcho(s *scmpCtx, total uint) {
	s.recv = 0
	s.sent = 0
	s.total = uint64(total)
	// Receive packet
	s.pktR = &spkt.ScnPkt{}
	s.ctR = scmp.ClassType{Class: scmp.C_General, Type: scmp.T_G_EchoReply}
	// Send packet
	s.infoS = &scmp.InfoEcho{Id: rnd.Uint64(), Seq: 0}
	s.pktS = newSCMPPkt(scmp.T_G_EchoRequest, s.infoS, nil)
	s.ctS = scmp.ClassType{Class: scmp.C_General, Type: scmp.T_G_EchoRequest}
}

func initRecordPath(s *scmpCtx, pathEntry *sciond.PathReplyEntry) {
	s.recv = 0
	s.sent = 0
	s.total = 1
	// Receive packet
	s.pktR = &spkt.ScnPkt{}
	s.ctR = scmp.ClassType{Class: scmp.C_General, Type: scmp.T_G_RecordPathReply}
	// Send packet
	ext := &scmp.Extn{Error: false, HopByHop: true}
	n := uint8(len(pathEntry.Path.Interfaces))
	s.infoS = &scmp.InfoRecordPath{Id: rnd.Uint64(), NumHops: 0, MaxHops: n}
	s.pktS = newSCMPPkt(scmp.T_G_RecordPathRequest, s.infoS, ext)
	s.ctS = scmp.ClassType{Class: scmp.C_General, Type: scmp.T_G_RecordPathRequest}
}

func updatePktTS(s *scmpCtx, ts time.Time) {
	scmpHdr := s.pktS.L4.(*scmp.Hdr)
	scmpHdr.Timestamp = uint64(ts.UnixNano()) / 1000
}

func updatePkt(s *scmpCtx) {
	switch info := s.infoS.(type) {
	case *scmp.InfoEcho:
		info.Seq += 1
		b := s.pktS.Pld.(common.RawBytes)
		info.Write(b[scmp.MetaLen:])
	}
}

func morePkts(s *scmpCtx) bool {
	return s.total == 0 || s.sent < s.total
}

func validatePkt(s *scmpCtx) error {
	_, ok := s.pktR.L4.(*scmp.Hdr)
	if ok == false {
		return common.NewBasicError("Not a SCMP header", nil)
	}
	scmpPld, ok := s.pktR.Pld.(*scmp.Payload)
	if ok == false {
		return common.NewBasicError("Not a SCMP payload)", nil)
	}
	switch s.ctR {
	case scmp.ClassType{Class: scmp.C_General, Type: scmp.T_G_EchoReply}:
		s.infoR, ok = scmpPld.Info.(*scmp.InfoEcho)
		if ok == false {
			return common.NewBasicError("Not an Info Echo type", nil,
				"type", common.TypeOf(s.infoR))
		}
	case scmp.ClassType{Class: scmp.C_General, Type: scmp.T_G_RecordPathReply}:
		s.infoR, ok = scmpPld.Info.(*scmp.InfoRecordPath)
		if ok == false {
			return common.NewBasicError("Not a Info RecordPath type", nil,
				"type", common.TypeOf(s.infoR))
		}
	}
	return nil
}

func prettyPrint(s *scmpCtx, pktLen int, now time.Time) {
	// Calculate return time
	scmpHdr := s.pktR.L4.(*scmp.Hdr)
	rtt := float64(now.UnixNano()-(int64(scmpHdr.Timestamp)*1000)) / 1000000
	switch info := s.infoR.(type) {
	case *scmp.InfoEcho:
		fmt.Printf("%d bytes from %s,[%s] scmp_seq=%d time=%.3fms\n",
			pktLen, s.pktR.SrcIA, s.pktR.SrcHost, info.Seq, rtt)
	case *scmp.InfoRecordPath:
		fmt.Printf("%d bytes from %s,[%s] time=%.3fms Hops=%d\n",
			pktLen, s.pktR.SrcIA, s.pktR.SrcHost, rtt, info.NumHops)
		for i := 0; i < int(info.NumHops); i++ {
			e := info.Entry(i)
			ts := e.TS - uint16(scmpHdr.Timestamp/1000)
			fmt.Printf(" %2d. %v %v %vms\n", i+1, e.IA, e.IfID, ts)
		}
	}
}
