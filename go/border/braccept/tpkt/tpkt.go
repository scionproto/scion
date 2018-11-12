package tpkt

import (
	"fmt"
	"hash"
	"net"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/lib/common"
)

// In hpkt, the common header is auto generated, ie. length, nextHdr, etc.
// The mergo package allows to merge structs, so any fields not set in the original struct
// are set with the fields of the struct we are merging with.

// PktGen is used for building the packet that will be sent to the border router.
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
