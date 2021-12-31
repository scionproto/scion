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

package router

import (
	"net"

	"golang.org/x/net/ipv4"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/topology"
)

var NewServices = newServices

type ProcessResult struct {
	processResult
}

func NewDP(
	external map[uint16]BatchConn,
	linkTypes map[uint16]topology.LinkType,
	internal BatchConn,
	internalNextHops map[uint16]*net.UDPAddr,
	svc map[addr.HostSVC][]*net.UDPAddr,
	local addr.IA,
	neighbors map[uint16]addr.IA,
	key []byte) *DataPlane {

	dp := &DataPlane{
		localIA:          local,
		external:         external,
		linkTypes:        linkTypes,
		neighborIAs:      neighbors,
		internalNextHops: internalNextHops,
		svc:              &services{m: svc},
		internal:         internal,
	}
	dp.SetKey(key)
	return dp
}

func (d *DataPlane) FakeStart() {
	d.running = true
}

func (d *DataPlane) ProcessPkt(ifID uint16, m *ipv4.Message) (ProcessResult, error) {

	p := newPacketProcessor(d, ifID)
	var srcAddr *net.UDPAddr
	// for real packets received from ReadBatch this is always non-nil.
	// Allow nil in test cases for brevity.
	if m.Addr != nil {
		srcAddr = m.Addr.(*net.UDPAddr)
	}
	result, err := p.processPkt(m.Buffers[0], srcAddr)
	return ProcessResult{processResult: result}, err
}

func ExtractServices(s *services) map[addr.HostSVC][]*net.UDPAddr {
	return s.m
}
