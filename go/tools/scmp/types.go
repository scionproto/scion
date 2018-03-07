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
	scmpMeta := scmp.Meta{InfoLen: uint8(info.Len())}
	pld := make(common.RawBytes, scmp.MetaLen+info.Len())
	scmpMeta.Write(pld)
	info.Write(pld[scmp.MetaLen:])
	scmpHdr := scmp.NewHdr(scmp.ClassType{Class: scmp.C_General, Type: t}, len(pld))

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

type scmpCtx struct {
	pkt     *spkt.ScnPkt
	pktType scmp.Type
	info    scmp.Info
	count   uint64
	num     uint64
}

func initSCMP(send, recv *scmpCtx, typeStr string, count uint, pathEntry *sciond.PathReplyEntry) {
	switch typeStr {
	case "echo":
		initEcho(send, false, count)
		initEcho(recv, true, count)
	default:
		fatal("Invalid SCMP type")
	}
}

func initEcho(s *scmpCtx, recv bool, count uint) {
	s.num = 0
	s.count = uint64(count)
	s.info = &scmp.InfoEcho{Id: rnd.Uint64(), Seq: 0}
	if recv {
		s.pkt = &spkt.ScnPkt{}
		s.pktType = scmp.T_G_EchoReply
	} else {
		ext := &scmp.Extn{Error: false, HopByHop: false}
		s.pkt = newSCMPPkt(scmp.T_G_EchoRequest, s.info, ext)
		s.pktType = scmp.T_G_EchoRequest
	}
}

func updatePktTS(s *scmpCtx, ts time.Time) {
	scmpHdr := s.pkt.L4.(*scmp.Hdr)
	scmpHdr.Timestamp = uint64(ts.UnixNano()) / 1000
}
func updatePkt(s *scmpCtx) {
	//updatePktTS(s, ts)
	s.num += 1
	switch info := s.info.(type) {
	case *scmp.InfoEcho:
		info.Seq += 1
		b := s.pkt.Pld.(common.RawBytes)
		info.Write(b[scmp.MetaLen:])
	}
}

func morePkts(s *scmpCtx) bool {
	return s.count == 0 || s.num < s.count
}

func validatePkt(s *scmpCtx) error {
	_, ok := s.pkt.L4.(*scmp.Hdr)
	if ok == false {
		return common.NewBasicError("Not a SCMP header", nil)
	}
	scmpPld, ok := s.pkt.Pld.(*scmp.Payload)
	if ok == false {
		return common.NewBasicError("Not a SCMP payload)", nil)
	}
	switch s.pktType {
	case scmp.T_G_EchoReply:
		s.info, ok = scmpPld.Info.(*scmp.InfoEcho)
		if ok == false {
			return common.NewBasicError("Not an Info Echo type", nil,
				"type", common.TypeOf(s.info))
		}
	}
	return nil
}

func prettyPrint(s *scmpCtx, pktLen int, now time.Time) {
	// Calculate return time
	scmpHdr := s.pkt.L4.(*scmp.Hdr)
	//rtt := now.Sub(time.Unix(0, int64(scmpHdr.Timestamp)*1000))
	rtt := now.UnixNano() - (int64(scmpHdr.Timestamp) * 1000)
	switch info := s.info.(type) {
	case *scmp.InfoEcho:
		fmt.Printf("%d bytes from %s,[%s] scmp_seq=%d time=%.3fms\n",
			pktLen, s.pkt.SrcIA, s.pkt.SrcHost, info.Seq, float64(rtt)/1000000)
	}
}
