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

package ifstate

import (
	"context"
	"net"
	"sync"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
)

// Pusher pushes interface state infos to all border routers to remove the
// revocations. It is called when an interface comes back up.
type Pusher struct {
	TopoProvider topology.Provider
	Intfs        *Interfaces
	Msgr         infra.Messenger
}

// Push removes the revocation for the given interface from all border routers.
func (p *Pusher) Push(ctx context.Context, ifid common.IFIDType) {
	intf := p.Intfs.Get(ifid)
	if intf == nil || intf.State() != Active {
		return
	}
	msg := &path_mgmt.IFStateInfos{
		Infos: []*path_mgmt.IFStateInfo{{
			IfID:   ifid,
			Active: true,
		}},
	}
	topo := p.TopoProvider.Get()
	wg := &sync.WaitGroup{}
	for id, br := range topo.BR {
		a := &snet.Addr{
			IA:      topo.ISD_AS,
			Host:    br.CtrlAddrs.PublicAddr(br.CtrlAddrs.Overlay),
			NextHop: br.CtrlAddrs.OverlayAddr(br.CtrlAddrs.Overlay),
		}
		p.sendToBr(ctx, id, a, msg, wg)
	}
	wg.Wait()
}

func (p *Pusher) sendToBr(ctx context.Context, id string, a net.Addr,
	msg *path_mgmt.IFStateInfos, wg *sync.WaitGroup) {

	wg.Add(1)
	go func() {
		defer log.LogPanicAndExit()
		defer wg.Done()
		if err := p.Msgr.SendIfStateInfos(ctx, msg, a, messenger.NextId()); err != nil {
			log.Error("[Pusher] Failed to send IfStateInfo to BR", "br", id, "err", err)
		}
	}()
}
