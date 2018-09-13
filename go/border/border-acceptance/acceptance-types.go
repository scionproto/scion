package main

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
)

type ifPktInfo struct {
	dev     string
	overlay *overlayInfo
	data    []byte
}

type segDef struct {
	inf  spath.InfoField
	hops []spath.HopField
}

type overlayInfo struct {
	SrcAddr string
	SrcPort uint16
	DstAddr string
	DstPort uint16
}

type addrInfo struct {
	SrcIA   string
	DstIA   string
	SrcHost string
	DstHost string
}

type pktInfo struct {
	Dev     string
	Overlay *overlayInfo
	InfoF   int
	HopF    int
	Addr    *addrInfo
	Path    []*segDef
}

type BRTest struct {
	BorderID string
	In       *pktInfo
	Out      []*pktInfo
}

type AddrHdr struct {
	DstIA, SrcIA     addr.IA
	DstHost, SrcHost addr.HostAddr
}

func (a *AddrHdr) Write(b common.RawBytes) int {
	// Address header
	offset := 0
	a.DstIA.Write(b[offset:])
	offset += addr.IABytes
	a.SrcIA.Write(b[offset:])
	offset += addr.IABytes
	// addr.HostAddr.Pack() is zero-copy, use it directly
	offset += copy(b[offset:], a.DstHost.Pack())
	offset += copy(b[offset:], a.SrcHost.Pack())
	// Zero memory padding
	addrPad := util.CalcPadding(offset, common.LineLen)
	zeroPad := b[offset : offset+addrPad]
	for i := range zeroPad {
		zeroPad[i] = 0
	}
	return offset + addrPad
}

func (a *AddrHdr) String() string {
	return fmt.Sprintf("DstIA: %s, SrcIA: %s, DstHost: %s, SrcHost: %s",
		a.DstIA, a.SrcIA, a.DstHost, a.SrcHost)
}
