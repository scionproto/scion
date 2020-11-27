// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
