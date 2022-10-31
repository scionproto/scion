package main

import (
	"fmt"
	"io"
	"net"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

// Path defines model for Path.
type Path struct {
	// Hex-string representing the paths fingerprint.
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
	Hops        []Hop  `json:"hops" yaml:"hops"`
	Sequence    string `json:"hops_sequence" yaml:"hops_sequence"`

	LocalIP net.IP `json:"local_ip,omitempty" yaml:"local_ip,omitempty"`

	// The internal UDP/IP underlay address of the SCION router that forwards traffic for this path.
	NextHop string `json:"next_hop" yaml:"next_hop"`
}

// Hop represents an hop on the path.
type Hop struct {
	ID common.IFIDType `json:"interface" yaml:"interface"`
	IA addr.IA         `json:"isd_as" yaml:"isd_as"`
}

// GetHops constructs a list of snet path interfaces from an snet path
func getHops(path snet.Path) []Hop {
	ifaces := path.Metadata().Interfaces
	var hops []Hop
	if len(ifaces) == 0 {
		return hops
	}
	for i := range ifaces {
		intf := ifaces[i]
		hops = append(hops, Hop{IA: intf.IA, ID: intf.ID})
	}
	return hops
}

// getPrintf returns a printf function for the "human" formatting flag and an empty one for machine
// readable format flags
func getPrintf(outputFlag string, writer io.Writer) (func(format string, ctx ...interface{}), error) {
	printf := func(format string, ctx ...interface{}) {}
	switch outputFlag {
	case "human":
		printf = func(format string, ctx ...interface{}) {
			fmt.Fprintf(writer, format, ctx...)
		}
		return printf, nil
	case "yaml", "json":
		return printf, nil
	default:
		return printf, serrors.New("format not supported", "format", outputFlag)
	}
}
