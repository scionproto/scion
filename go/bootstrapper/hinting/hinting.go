package hinting

import (
	"net"

	"github.com/scionproto/scion/go/lib/log"
)

const (
	DiscoveryPort uint16 = 8041
)

type HintGenerator interface {
	Generate(chan<- net.IP)
}

type MOCKHintGeneratorConf struct {
	Enable  bool
	Address string
}

var _ HintGenerator = (*MockHintGenerator)(nil)

type MockHintGenerator struct {
	cfg *MOCKHintGeneratorConf
}

func NewMockHintGenerator(cfg *MOCKHintGeneratorConf) *MockHintGenerator {
	return &MockHintGenerator{cfg}
}

func (m *MockHintGenerator) Generate(ipHintsChan chan<- net.IP) {
	if !m.cfg.Enable {
		return
	}
	ip := net.ParseIP(m.cfg.Address)
	if ip == nil {
		log.Error("Invalid IP Address for mock generator", "ip", ip)
	} else {
		ipHintsChan <- ip
	}
}
