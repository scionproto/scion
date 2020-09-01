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
	"sync"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/topology"
)

// PusherConf is the configuration to create a new pusher.
type PusherConf struct {
	TopoProvider topology.Provider
	Intfs        *Interfaces
	StateSender  InterfaceStateSender
}

// Pusher pushes interface state infos to all border routers to remove the
// revocations. It is called when an interface comes back up.
type Pusher struct {
	topoProvider topology.Provider
	intfs        *Interfaces
	pusher       brPusher
}

// New creates a new interface state pusher.
func (cfg PusherConf) New() *Pusher {
	return &Pusher{
		topoProvider: cfg.TopoProvider,
		intfs:        cfg.Intfs,
		pusher: brPusher{
			sender: cfg.StateSender,
			mode:   "pusher",
		},
	}
}

// Push removes the revocation for the given interface from all border routers.
func (p *Pusher) Push(ctx context.Context, ifID common.IFIDType) {
	intf := p.intfs.Get(ifID)
	if intf == nil || intf.State() != Active {
		return
	}
	msg := []InterfaceState{{ID: uint16(ifID)}}
	wg := &sync.WaitGroup{}
	p.pusher.sendIfStateToAllBRs(ctx, msg, p.topoProvider.Get(), wg)
	wg.Wait()
}
