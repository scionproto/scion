package pkti

import (
	"hash"
	"net"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/lib/common"
)

var HashMac hash.Hash

// In hpkt, the common header is auto generated, ie. length, nextHdr, etc.
// The mergo package allows to merge structs, so any fields not set in the original struct
// are set with the fields of the struct we are merging with.

// PktGen is used for building the packet that will be sent to the border router.
type PktGen interface {
	Setup()
	GetDev() string
	GetOverlay(net.HardwareAddr) ([]gopacket.SerializableLayer, error)
	Pack(net.HardwareAddr, hash.Hash) (common.RawBytes, error)
	GetPktInfo() *PktInfo
}

// PktMatch is used to compare the received packet against the expected packet.
type PktMatch interface {
	GetDev() string
	Merge(*PktInfo)
	Match(gopacket.Packet) error
}
