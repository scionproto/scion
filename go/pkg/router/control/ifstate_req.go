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

package control

import (
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/border/rctrl/grpc"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/router/control/internal/metrics"
)

const (
	// ifStateFreq is how often the router will request an Interface State update
	// from the beacon service.
	ifStateFreq = 30 * time.Second
)

// ifStateReq handles generating periodic Interface State Request (IFStateReq)
// packets that are sent to the local Beacon Service (BS).
// IFStateReqs are mostly needed on startup, to make sure the border router is aware
// of the status of the local interfaces. The BS normally updates the border routers
// everytime an interface state changes, so this is only needed as a fail-safe after
// startup.
func ifStateReq(c *IACtx, updater grpc.IfStateUpdater) {
	if err := updateInterfaces(c, updater); err != nil {
		log.Error(err.Error())
	}
	ticker := time.NewTicker(ifStateFreq)
	defer ticker.Stop()
	for {
		select {
		case <-c.Stop:
			// Nothing to cleanup here, so just exit.
			return
		case <-ticker.C:
			if err := updateInterfaces(c, updater); err != nil {
				log.Error(err.Error())
			}
		}
	}
}

func updateInterfaces(c *IACtx, updater grpc.IfStateUpdater) error {
	cl := metrics.ControlLabels{
		Result: metrics.ErrProcess,
	}
	bsAddrs, err := c.BRConf.Topo.Multicast(addr.SvcCS)
	if err != nil {
		cl.Result = metrics.ErrResolveSVC
		metrics.Control.SentIFStateReq(cl).Inc()
		return serrors.WrapStr("resolving SVC BS multicast", err)
	}
	servers := make([]net.Addr, 0, len(bsAddrs))
	for _, bs := range bsAddrs {
		servers = append(servers, &net.TCPAddr{IP: bs.IP, Port: bs.Port, Zone: bs.Zone})
	}
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	return updater.UpdateIfState(ctx, servers)
}
