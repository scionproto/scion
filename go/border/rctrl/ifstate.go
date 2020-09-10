// Copyright 2018 ETH Zurich, Anapaya Systems
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

package rctrl

import (
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/border/metrics"
	"github.com/scionproto/scion/go/border/rctrl/grpc"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

const (
	// ifStateFreq is how often the router will request an Interface State update
	// from the beacon service.
	ifStateFreq = 30 * time.Second
)

// IFStateUpdate handles generating periodic Interface State Request (IFStateReq)
// packets that are sent to the local Beacon Service (BS), as well as
// processing the Interface State updates. IFStateReqs are mostly needed on
// startup, to make sure the border router is aware of the status of the local
// interfaces. The BS normally updates the border routers everytime an
// interface state changes, so this is only needed as a fail-safe after
// startup.
func ifStateUpdate(updater grpc.IfStateUpdater) {
	if err := updateInterfaces(updater); err != nil {
		logger.Error(err.Error())
	}
	for range time.Tick(ifStateFreq) {
		if err := updateInterfaces(updater); err != nil {
			logger.Error(err.Error())
		}
	}
}

func updateInterfaces(updater grpc.IfStateUpdater) error {
	cl := metrics.ControlLabels{
		Result: metrics.ErrProcess,
	}
	bsAddrs, err := rctx.Get().Conf.Topo.Multicast(addr.SvcCS)
	if err != nil {
		cl.Result = metrics.ErrResolveSVC
		metrics.Control.SentIFStateReq(cl).Inc()
		return common.NewBasicError("Resolving SVC BS multicast", err)
	}
	servers := make([]net.Addr, 0, len(bsAddrs))
	for _, bs := range bsAddrs {
		servers = append(servers, &net.TCPAddr{IP: bs.IP, Port: bs.Port, Zone: bs.Zone})
	}
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	return updater.UpdateIfState(ctx, servers)
}
