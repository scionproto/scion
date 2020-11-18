package hinting

import "net"

const (
	DiscoveryPort uint16 = 8041
)

type HintGenerator interface {
	Generate(chan net.IP)
}
