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
	"sync"
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

// Sender is used to send payloads on a one-hop path.
type Sender struct {
	// SrcIA is the ISD-AS of the local AS.
	SrcIA addr.IA
	// Addr is the address that is set as the source.
	Addr *addr.AppAddr
	// Conn is the connection to sent the packets.
	Conn *snet.SCIONPacketConn
	// HFMacPool is the mac pool to issue hop fields.
	HFMacPool *sync.Pool
}

// Send sends the payload on a one-hop path.
func (s *Sender) Send(dst snet.SCIONAddress, ifid common.IFIDType, nextHop *overlay.OverlayAddr,
	pld common.Payload, infoTime time.Time) error {

	pkt, err := s.Pkt(dst, ifid, pld, infoTime)
	if err != nil {
		return common.NewBasicError("Unable to create packet", err)
	}
	return s.Conn.WriteTo(pkt, nextHop)
}

// Pkt creates a scion packet with a one-hop path and the payload.
func (s *Sender) Pkt(dst snet.SCIONAddress, ifid common.IFIDType, pld common.Payload,
	now time.Time) (*snet.SCIONPacket, error) {

	path, err := s.CreatePath(ifid, now)
	if err != nil {
		return nil, err
	}
	return s.CreatePkt(dst, path, pld), nil
}

// CreatePath creates the one-hop path and initializes it.
func (s *Sender) CreatePath(ifid common.IFIDType, now time.Time) (*Path, error) {

	mac := s.HFMacPool.Get().(hash.Hash)
	defer s.HFMacPool.Put(mac)
	path, err := spath.NewOneHop(s.SrcIA.I, ifid, time.Now(), spath.DefaultHopFExpiry, mac)
	if err != nil {
		return nil, err
	}
	return (*Path)(path), path.InitOffsets()
}

// CreatePkt creates a scion packet with a one-hop extension, and the
// provided path and payload.
func (s *Sender) CreatePkt(dst snet.SCIONAddress, path *Path,
	pld common.Payload) *snet.SCIONPacket {

	pkt := &snet.SCIONPacket{
		SCIONPacketInfo: snet.SCIONPacketInfo{
			Destination: dst,
			Source: snet.SCIONAddress{
				IA:   s.SrcIA,
				Host: s.Addr.L3,
			},
			Path:       (*spath.Path)(path),
			Extensions: []common.Extension{&layers.ExtnOHP{}},
			L4Header: &l4.UDP{
				SrcPort: s.Addr.L4.Port(),
			},
			Payload: pld,
		},
	}
	return pkt
}
