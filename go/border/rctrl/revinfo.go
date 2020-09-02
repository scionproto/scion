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
	"github.com/scionproto/scion/go/border/rpkt"
)

// RevInfoFwd takes RevInfos, and forwards them to the local Beacon Service
// (BS) and Path Service (PS).
func revInfoFwd(revInfoQ chan rpkt.RawSRevCallbackArgs, sender grpc.RevocationSender) {
	cl := metrics.ControlLabels{}
	// Run forever.
	for args := range revInfoQ {
		revInfo, err := args.SignedRevInfo.RevInfo()
		if err != nil {
			cl.Result = metrics.ErrParse
			metrics.Control.ReadRevInfos(cl).Inc()
			logger.Error("Error getting RevInfo from SignedRevInfo", "err", err)
			continue
		}
		cl.Result = metrics.Success
		metrics.Control.ReadRevInfos(cl).Inc()
		uniqueAddrs := make(map[string]net.Addr)
		for _, svcAddr := range args.Addrs {
			a, err := rctx.Get().Conf.Topo.Anycast(svcAddr.Base())
			if err != nil {
				logger.Error("Resolving svc addr", "err", err, "addr", svcAddr)
				continue
			}
			tcpA := &net.TCPAddr{IP: a.IP, Port: a.Port, Zone: a.Zone}
			uniqueAddrs[tcpA.String()] = tcpA
		}
		var addrs []net.Addr
		for _, a := range uniqueAddrs {
			addrs = append(addrs, a)
		}
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		if err := sender.SendRevocation(ctx, args.SignedRevInfo, addrs); err != nil {
			logger.Error("Forwarding revocation",
				"revInfo", revInfo.String(), "targets", addrs, "err", err)
		} else {
			logger.Debug("Forwarding revocation", "revInfo", revInfo.String(), "targets", addrs)
		}
		cancelF()
	}
}
