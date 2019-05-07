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
	"time"

	"github.com/scionproto/scion/go/beacon_srv/internal/onehop"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/ifid"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
)

var _ periodic.Task = (*Sender)(nil)

// Sender sends ifid keepalive messages on all border routers.
type Sender struct {
	*onehop.Sender
	Signer       infra.Signer
	TopoProvider topology.Provider
}

// Run sends ifid keepalive messages on all border routers.
func (s *Sender) Run(_ context.Context) {
	topo := s.TopoProvider.Get()
	if topo == nil {
		log.Error("[KeepaliveSender] Unable to send keepalive, no topology set")
		return
	}
	for ifid, intf := range topo.IFInfoMap {
		pld, err := s.createPld(ifid)
		if err != nil {
			log.Error("[KeepaliveSender] Unable to create payload", "err", err)
			continue
		}
		msg := &onehop.Msg{
			Dst: snet.SCIONAddress{
				IA:   intf.ISD_AS,
				Host: addr.SvcBS | addr.SVCMcast,
			},
			Ifid:     ifid,
			InfoTime: time.Now(),
			Pld:      pld,
		}
		ov := intf.InternalAddrs.PublicOverlay(intf.InternalAddrs.Overlay)
		if err := s.Send(msg, ov); err != nil {
			log.Error("[KeepaliveSender] Unable to send packet", "err", err)
		}
	}
}

// createPld creates a ifid keepalive payload that is signed and packed.
func (s *Sender) createPld(origIfid common.IFIDType) (common.Payload, error) {
	pld, err := ctrl.NewPld(&ifid.IFID{OrigIfID: origIfid}, nil)
	if err != nil {
		return nil, err
	}
	spld, err := pld.SignedPld(s.Signer)
	if err != nil {
		return nil, err
	}
	return spld.PackPld()
}
