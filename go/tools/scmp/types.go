package main

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
)

func newSCMPPkt(t scmp.Type, info scmp.Info, ext common.Extension) *spkt.ScnPkt {
	scmpMeta := scmp.Meta{InfoLen: uint8(info.Len())}
	assert.Must((scmp.MetaLen+info.Len())%common.LineLen == 0, "Bad SCMP payload length")
	pld := make(common.RawBytes, scmp.MetaLen+info.Len())
	scmpMeta.Write(pld)
	info.Write(pld[scmp.MetaLen:])
	scmpHdr := scmp.NewHdr(scmp.ClassType{Class: scmp.C_General, Type: t}, len(pld))
	exts := make([]common.Extension, 1)
	exts[0] = ext

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

type scmpI interface {
	fmt.Stringer
	scmpCommonI
	init()
	sendNext() bool
	recvNext() bool
	validate() error
}

func newScmp(typeStr string) scmpI {
	var ret scmpI
	switch {
	case typeStr == "echo":
		ret = &scmpEcho{}
	default:
		logFatal("Invalid SCMP type")
	}
	ret.init()
	return ret
}

/*
 * SCMP Echo
 */
var _ scmpI = (*scmpEcho)(nil)

type scmpEcho struct {
	scmpCommon
	infoSend *scmp.InfoEcho
	infoRecv *scmp.InfoEcho
	total    uint
	sent     uint
	recv     uint
}

func (s *scmpEcho) init() {
	s.sent = 0
	s.total = *count // flag
	s.recv = 0
	s.infoSend = &scmp.InfoEcho{Id: rnd.Uint64(), Seq: 0}
	ext := &scmp.Extn{Error: false, HopByHop: false}
	s.pktS = newSCMPPkt(scmp.T_G_EchoRequest, s.infoSend, ext)
	s.pktR = &spkt.ScnPkt{DstIA: &addr.ISD_AS{}, SrcIA: &addr.ISD_AS{}, Path: &spath.Path{}}
}

func (s *scmpEcho) sendNext() bool {
	s.sent += 1
	s.infoSend.Seq += 1
	b := s.pktS.Pld.(common.RawBytes)
	s.infoSend.Write(b[scmp.MetaLen:])
	return s.sent < s.total
}

func (s *scmpEcho) recvNext() bool {
	s.recv += 1
	return s.recv < s.total
}

func (s *scmpEcho) validate() error {
	scmpHdr, ok := s.pktR.L4.(*scmp.Hdr)
	if ok == false {
		return common.NewBasicError("Not a SCMP header", nil)
	}
	if scmpHdr.Type != scmp.T_G_EchoReply {
		return common.NewBasicError("Bad type", nil,
			"Received", scmpHdr.Type, "Expected", scmp.T_G_EchoReply)
	}
	scmpPld, ok := s.pktR.Pld.(*scmp.Payload)
	if ok == false {
		return common.NewBasicError("Not a SCMP payload)", nil)
	}
	s.infoRecv, ok = scmpPld.Info.(*scmp.InfoEcho)
	if ok == false {
		return common.NewBasicError("Not a Info Echo type", nil)
	}
	return nil
}

func (s *scmpEcho) String() string {
	return fmt.Sprintf("scmp_seq=%v", s.infoRecv.Seq)
}

/*
 * SCMP Common
 */
type scmpCommonI interface {
	pktSend() *spkt.ScnPkt
	pktRecv() *spkt.ScnPkt
	setTimestamp(uint64)
	getTimestamp() uint64
}

var _ scmpCommonI = scmpCommon{}

type scmpCommon struct {
	pktS *spkt.ScnPkt
	pktR *spkt.ScnPkt
}

func (s scmpCommon) pktSend() *spkt.ScnPkt {
	return s.pktS
}

func (s scmpCommon) pktRecv() *spkt.ScnPkt {
	return s.pktR
}

func (s scmpCommon) setTimestamp(ts uint64) {
	scmpHdr := s.pktS.L4.(*scmp.Hdr)
	scmpHdr.Timestamp = ts
}

func (s scmpCommon) getTimestamp() uint64 {
	scmpHdr := s.pktR.L4.(*scmp.Hdr)
	return scmpHdr.Timestamp
}
