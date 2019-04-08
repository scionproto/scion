// Copyright 2019 Anapaya Systems
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
	"hash"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

// Path is a one-hop path.
type Path spath.Path

// Msg defines the message payload and the path it is sent on.
type Msg struct {
	// Dst is the destination of the message.
	Dst snet.SCIONAddress
	// Ifid is the IFID the message is sent on.
	Ifid common.IFIDType
	// InfoTime is the timestamp set in the info field.
	InfoTime time.Time
	// Pld is the message payload.
	Pld common.Payload
}

// Sender is used to send payloads on a one-hop path.
type Sender struct {
	// IA is the ISD-AS of the local AS.
	IA addr.IA
	// Addr is the address that is set as the source.
	Addr *addr.AppAddr
	// Conn is used to send the packets.
	Conn *snet.SCIONPacketConn
	// MAC is the mac to issue hop fields.
	MAC hash.Hash
}

// Send sends the payload on a one-hop path.
func (s *Sender) Send(msg *Msg, nextHop *overlay.OverlayAddr) error {
	pkt, err := s.CreatePkt(msg)
	if err != nil {
		return common.NewBasicError("Unable to create packet", err)
	}
	return s.Conn.WriteTo(pkt, nextHop)
}

// CreatePkt creates a scion packet with a one-hop path and the payload.
func (s *Sender) CreatePkt(msg *Msg) (*snet.SCIONPacket, error) {

	path, err := s.CreatePath(msg.Ifid, msg.InfoTime)
	if err != nil {
		return nil, err
	}
	pkt := &snet.SCIONPacket{
		SCIONPacketInfo: snet.SCIONPacketInfo{
			Destination: msg.Dst,
			Source: snet.SCIONAddress{
				IA:   s.IA,
				Host: s.Addr.L3,
			},
			Path:       (*spath.Path)(path),
			Extensions: []common.Extension{&layers.ExtnOHP{}},
			L4Header: &l4.UDP{
				SrcPort: s.Addr.L4.Port(),
			},
			Payload: msg.Pld,
		},
	}
	return pkt, nil
}

// CreatePath creates the one-hop path and initializes it.
func (s *Sender) CreatePath(ifid common.IFIDType, now time.Time) (*Path, error) {
	s.MAC.Reset()
	path, err := spath.NewOneHop(s.IA.I, ifid, time.Now(), spath.DefaultHopFExpiry, s.MAC)
	if err != nil {
		return nil, err
	}
	return (*Path)(path), path.InitOffsets()
}
