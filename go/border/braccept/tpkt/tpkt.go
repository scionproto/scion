// Package tpkt contains interfaces, types, and methods that i) allow the creation of potentially
// malformed SCION packets and ii) enable comparison between expected and received SCION packets.
//
// We cannot always use the hpkt package here, since it disallows some forms of malformed packets,
// e.g., by autogenerating the common header from other input.
//
// We use the mergo package to easily merge different structs. It does so by setting any unset
// fields in a struct with the corresponding fields in the struct to be merge in. This enables us
// to only specify packet diffs between original and expected packets when defining test cases.
package tpkt

import (
	"fmt"
	"hash"
	"net"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
)

// Packer is used for building the packet that will be sent to the border router.
type Packer interface {
	GetDev() string
	Pack(net.HardwareAddr, hash.Hash) (common.RawBytes, error)
	fmt.Stringer
}

// Matcher is used to compare the received packet against the expected packet.
type Matcher interface {
	Match(string, gopacket.Packet) error
}

var _ Packer = (*GenCmnHdrPkt)(nil)

// GenCmnHdrPkt merges the common header specified in the test with an auto generated common header.
type GenCmnHdrPkt struct {
	Pkt
}

func (p *GenCmnHdrPkt) Pack(dstMac net.HardwareAddr, mac hash.Hash) (common.RawBytes, error) {
	p.mergeCmnHdr()
	return p.Pkt.Pack(dstMac, mac)
}

var _ Packer = (*Raw)(nil)

// Raw does not do any type of merging, it just uses the specified packet info from the test.
type Raw struct {
	Pkt
}

func (p *Raw) GenCmnHdr() {
	// Do nothing
}

func GenL4UDP(src, dst uint16) *l4.UDP {
	return &l4.UDP{SrcPort: src, DstPort: dst}
}
