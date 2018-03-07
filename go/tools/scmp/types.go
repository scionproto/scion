package main

import (
	"fmt"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
)

func newSCMPPkt(t scmp.Type, info scmp.Info, ext common.Extension) *spkt.ScnPkt {
	scmpMeta := scmp.Meta{InfoLen: uint8(info.Len())}
	pld := make(common.RawBytes, scmp.MetaLen+info.Len())
	scmpMeta.Write(pld)
	info.Write(pld[scmp.MetaLen:])
	scmpHdr := scmp.NewHdr(scmp.ClassType{Class: scmp.C_General, Type: t}, len(pld))
	scmpHdr.Timestamp = uint64(time.Now().UnixNano()) / 1000

	pkt := &spkt.ScnPkt{
		DstIA:   remote.IA,
		SrcIA:   local.IA,
		DstHost: remote.Host,
		SrcHost: local.Host,
		Path:    remote.Path,
		HBHExt:  []common.Extension{ext},
		L4:      scmpHdr,
		Pld:     pld,
	}
	return pkt
}

type scmpPkt struct {
	pkt     *spkt.ScnPkt
	pktType scmp.Type
	info    scmp.Info
	count   uint64
	num     uint64
}

func initSCMP(send, recv *scmpPkt, typeStr string, count uint, pathEntry *sciond.PathReplyEntry) {
	switch typeStr {
	case "echo":
		initEcho(send, false, count)
		initEcho(recv, true, count)
	default:
		fatal("Invalid SCMP type")
	}
}

func initEcho(s *scmpPkt, recv bool, count uint) {
	s.num = 0
	s.count = uint64(count)
	s.info = &scmp.InfoEcho{Id: rnd.Uint64(), Seq: 0}
	if recv {
		// FIXME application should not need to initialize this to parse a packet,
		// hpkt.parseCtx.parse() should take care of it
		s.pkt = &spkt.ScnPkt{DstIA: &addr.ISD_AS{}, SrcIA: &addr.ISD_AS{}, Path: &spath.Path{}}
		s.pktType = scmp.T_G_EchoReply
	} else {
		ext := &scmp.Extn{Error: false, HopByHop: false}
		s.pkt = newSCMPPkt(scmp.T_G_EchoRequest, s.info, ext)
		s.pktType = scmp.T_G_EchoRequest
	}
}

func updateNext(s *scmpPkt, ts time.Time) bool {
	scmpHdr := s.pkt.L4.(*scmp.Hdr)
	scmpHdr.Timestamp = uint64(ts.UnixNano()) / 1000
	s.num += 1
	switch info := s.info.(type) {
	case *scmp.InfoEcho:
		info.Seq += 1
		b := s.pkt.Pld.(common.RawBytes)
		info.Write(b[scmp.MetaLen:])
	}
	return s.count == 0 || s.num < s.count
}

func validatePkt(s *scmpPkt) error {
	scmpHdr, ok := s.pkt.L4.(*scmp.Hdr)
	if ok == false {
		return common.NewBasicError("Not a SCMP header", nil)
	}
	scmpPld, ok := s.pkt.Pld.(*scmp.Payload)
	if ok == false {
		return common.NewBasicError("Not a SCMP payload)", nil)
	}
	if scmpHdr.Type != s.pktType {
		return common.NewBasicError("Bad type", nil,
			"Received", scmpHdr.Type, "Expected", s.pktType)
	}
	switch s.pktType {
	case scmp.T_G_EchoReply:
		s.info, ok = scmpPld.Info.(*scmp.InfoEcho)
		if ok == false {
			return common.NewBasicError("Not a Info Echo type", nil, "type", common.TypeOf(s.info))
		}
	}
	return nil
}

func prettyPrint(s *scmpPkt, pktLen int, now time.Time) {
	// Calculate return time
	scmpHdr := s.pkt.L4.(*scmp.Hdr)
	retTime := now.Sub(time.Unix(0, int64(scmpHdr.Timestamp)*1000))
	switch info := s.info.(type) {
	case *scmp.InfoEcho:
		fmt.Printf("%d bytes from %v,[%v] scmp_seq=%v time=%v\n",
			pktLen, s.pkt.SrcIA, s.pkt.SrcHost, info.Seq, retTime)
	}
}
