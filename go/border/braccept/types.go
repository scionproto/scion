package main

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/kormat/fmt15"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/spkt"
)

type BRTest struct {
	Desc string
	In   PktGen
	Out  []PktMatch
}

func (t *BRTest) Summary(testPass bool) string {
	var result string
	if testPass {
		result = pass()
	} else {
		result = fail()
	}
	var str []string
	str = append(str, fmt.Sprintf("Test %s: %s", t.Desc, result))
	pi := t.In.GetPktInfo()
	if a := pi.AddrHdr; a != nil {
		str = append(str, fmt.Sprintf("\t%s,[%s] -> %s,[%s]",
			a.SrcIA, a.SrcHost, a.DstIA, a.DstHost))
	}
	if pi.Path != nil {
		str = append(str, printSegments(pi.Path.Segs, "\t", "\n"))
	}
	return strings.Join(str, "\n")
}

const (
	//	defColorFmt = "\x1b[%dm%s\x1b[0m"
	passUni = "\u2714"
	failUni = "\u2715"
	green   = 32
	red     = 31
)

func pass() string {
	//	return fmt.Sprintf(defColorFmt, green, passUni)
	return fmt15.ColorStr(passUni, green)
}

func fail() string {
	//	return fmt.Sprintf(defColorFmt, red, failUni)
	return fmt15.ColorStr(failUni, red)
}

type PktGen interface {
	Setup()
	GetDev() string
	GetOverlay() []gopacket.SerializableLayer
	Pack() common.RawBytes
	GetPktInfo() *PktInfo
}

type PktMatch interface {
	GetDev() string
	Merge(*PktInfo)
	Match(gopacket.Packet) error
}

var _ PktGen = (*PktGenCmn)(nil)
var _ PktMatch = (*PktGenCmn)(nil)

// In hpkt, the common header is auto generated, ie. length, nextHdr, etc.
// The mergo package allows to merge structs, so any fields not set in the original struct
// are set with the fields of the struct we are merging with.

// PktGenCmn merges the common header specified in the test with an auto generated common header.
type PktGenCmn struct {
	PktInfo
}

// Generate common header from packet info and replace the values provided by the user.
func (p *PktGenCmn) Merge(_ *PktInfo) {
	p.mergeCmnHdr()
}

func (p *PktGenCmn) Setup() {
	p.mergeCmnHdr()
}

var _ PktGen = (*PktMerge)(nil)
var _ PktMatch = (*PktMerge)(nil)

// PktMerge does like PktGenCmn plus also takes any other fields from a base packet.
// The aceptance framework will merge the expected packets with the sent packet, such as the
// expected packet only specifies the information that varies with respect to the packet sent.
type PktMerge struct {
	PktInfo
}

func (p *PktMerge) Setup() {
	p.mergeCmnHdr()
}

var _ PktGen = (*PktRaw)(nil)
var _ PktMatch = (*PktRaw)(nil)

// PktRaw does not do any type of merge, it just takes the specified packet info from the test.
type PktRaw struct {
	PktInfo
}

func (p *PktRaw) GetDev() string {
	return p.Dev
}

func (p *PktRaw) Merge(pi *PktInfo) {
	// Do nothing
}

func (p *PktRaw) Setup() {
	// Do nothing
}

var _ PktGen = (*HpktInfo)(nil)
var _ PktMatch = (*HpktInfo)(nil)

// HpktInfo behaves like PktMerge but it uses hpkt to build the packet instead of the custom
// building logic implemented by default.
// Basically, it creates a ScnPkt frmo the PktInfo in the test and calls hpkt.WriteScnPkt.
type HpktInfo struct {
	PktInfo
}

// Generate a ScnPkt when use hpkt to build it
func (pi *HpktInfo) Pack() common.RawBytes {
	// Complain if CmnHdr has been specified
	if pi.CmnHdr != nil {
		panic("PktInfoHpkt does not support custom CmnHdr")
	}
	if pi.L4 == nil {
		panic("PktInfoHpkt requires L4 header")
	}
	// Write SCION path
	pi.Path.Raw = make(common.RawBytes, pi.Path.Segs.Len())
	writeScnPath(pi.Path.Segs, pi.Path.Raw)
	// Create ScnPkt
	scn := &spkt.ScnPkt{
		DstIA:   pi.AddrHdr.DstIA,
		SrcIA:   pi.AddrHdr.SrcIA,
		DstHost: pi.AddrHdr.DstHost,
		SrcHost: pi.AddrHdr.SrcHost,
		Path:    &pi.Path.Path,
		HBHExt:  pi.Exts, // XXX E2E are not supported yet
		L4:      pi.L4,
		Pld:     pi.Pld,
	}
	if scn.Pld == nil {
		scn.Pld = new(common.RawBytes)
	}
	// Make space in buffer
	scnLen := scn.TotalLen()
	buf := make(common.RawBytes, scnLen)
	_, err = hpkt.WriteScnPkt(scn, buf)
	if err != nil {
		panic(err)
	}
	overlayLayers := pi.GetOverlay()
	l := make([]gopacket.SerializableLayer, len(overlayLayers)+1)
	for i, _ := range overlayLayers {
		l[i] = overlayLayers[i]
	}
	l[len(overlayLayers)] = gopacket.Payload(buf)
	pkt := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(pkt, options, l...); err != nil {
		panic(err)
	}
	return common.RawBytes(pkt.Bytes())
}

func (p *HpktInfo) Setup() {
	// Do nothing
}
