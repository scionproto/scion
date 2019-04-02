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

package keepalive

import (
	"context"
	"hash"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/ifid"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
)

var _ periodic.Task = (*Sender)(nil)

// Sender sends ifid keepalive messages on all border routers.
type Sender struct {
	Conn      *snet.SCIONPacketConn
	Addr      *addr.AppAddr
	HFMacPool *sync.Pool
	Signer    ctrl.Signer
}

// Run sends ifid keepalive messages on all border routers.
func (s *Sender) Run(_ context.Context) {
	topo := itopo.Get()
	if topo == nil {
		log.Error("[KeepaliveSender] Unable to send keepalive, no topology set")
		return
	}
	for ifid, intf := range topo.IFInfoMap {
		pkt, err := s.createPkt(topo, ifid, intf, time.Now())
		if err != nil {
			log.Error("[KeepaliveSender] Unable to create packet", "err", err)
			continue
		}
		brAddr := intf.InternalAddrs
		if err := s.Conn.WriteTo(pkt, brAddr.PublicOverlay(brAddr.Overlay)); err != nil {
			log.Error("[KeepaliveSender] Unable to send packet", "err", err)
		}
	}
}

// createPkt creates a scion packet with a one-hop path and the ifid keepalive payload.
func (s *Sender) createPkt(topo *topology.Topo, origIfid common.IFIDType, intf topology.IFInfo,
	now time.Time) (*snet.SCIONPacket, error) {

	path, err := s.createPath(topo.ISD_AS.I, origIfid, now)
	if err != nil {
		return nil, err
	}
	pld, err := s.createPld(origIfid)
	if err != nil {
		return nil, err
	}
	pkt := &snet.SCIONPacket{
		SCIONPacketInfo: snet.SCIONPacketInfo{
			Destination: snet.SCIONAddress{
				IA:   intf.ISD_AS,
				Host: addr.SvcBS | addr.SVCMcast,
			},
			Source: snet.SCIONAddress{
				IA:   topo.ISD_AS,
				Host: s.Addr.L3,
			},
			Path:       path,
			Extensions: []common.Extension{layers.ExtnOHP{}},
			L4Header: &l4.UDP{
				SrcPort: s.Addr.L4.Port(),
			},
			Payload: pld,
		},
	}
	return pkt, nil
}

// createPath creates the one-hop path and initializes it.
func (s *Sender) createPath(isd addr.ISD, origIfid common.IFIDType,
	now time.Time) (*spath.Path, error) {

	mac := s.HFMacPool.Get().(hash.Hash)
	defer s.HFMacPool.Put(mac)
	path, err := spath.NewOneHop(isd, origIfid, time.Now(), spath.DefaultHopFExpiry, mac)
	if err != nil {
		return nil, err
	}
	return path, path.InitOffsets()
}

// createPld creates a ifid keepalive payload that is signed and packed.
func (s *Sender) createPld(origIfid common.IFIDType) (common.Payload, error) {
	pld, err := ctrl.NewPld(&ifid.IFID{OrigIfID: origIfid}, nil)
	if err != nil {
		return nil, err
	}
	spld, err := s.Signer.Sign(pld)
	if err != nil {
		return nil, err
	}
	return spld.PackPld()
}
