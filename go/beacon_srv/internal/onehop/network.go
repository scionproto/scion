// Copyright 2019 ETH Zurich
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

package onehop

import (
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/snet"
)

var _ snet.PacketDispatcherService = (*OHPPacketDispatcherService)(nil)

// OHPPacketDispatcherService creates sockets where all packets have the OHP
// extension enabled.
type OHPPacketDispatcherService struct {
	snet.PacketDispatcherService
}

func (s *OHPPacketDispatcherService) RegisterTimeout(ia addr.IA, public *addr.AppAddr,
	bind *overlay.OverlayAddr, svc addr.HostSVC,
	timeout time.Duration) (snet.PacketConn, uint16, error) {

	conn, port, err := s.PacketDispatcherService.RegisterTimeout(ia, public, bind, svc, timeout)
	if err != nil {
		return conn, port, err
	}
	return &ohpPacketConn{PacketConn: conn}, port, err
}

var _ snet.PacketConn = (*ohpPacketConn)(nil)

type ohpPacketConn struct {
	snet.PacketConn
}

func (c *ohpPacketConn) WriteTo(pkt *snet.SCIONPacket, ov *overlay.OverlayAddr) error {
	return c.PacketConn.WriteTo(
		&snet.SCIONPacket{
			Bytes: pkt.Bytes,
			SCIONPacketInfo: snet.SCIONPacketInfo{
				Destination: pkt.Destination,
				Source:      pkt.Source,
				Path:        pkt.Path,
				Extensions:  append(pkt.Extensions, &layers.ExtnOHP{}),
				L4Header:    pkt.L4Header,
				Payload:     pkt.Payload,
			},
		},
		ov,
	)
}
