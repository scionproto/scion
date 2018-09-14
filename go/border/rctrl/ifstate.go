// Copyright 2018 ETH Zurich
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
	"time"

	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
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
func ifStateUpdate() {
	defer log.LogPanicAndExit()
	genIFStateReq()
	for range time.Tick(ifStateFreq) {
		genIFStateReq()
	}
}

// genIFStateReq generates an Interface State request packet to the local beacon service.
func genIFStateReq() {
	cpld, err := ctrl.NewPathMgmtPld(&path_mgmt.IFStateReq{}, nil, nil)
	if err != nil {
		logger.Error("Generating IFStateReq Ctrl payload", "err", err)
		return
	}
	scpld, err := cpld.SignedPld(ctrl.NullSigner)
	if err != nil {
		logger.Error("Generating IFStateReq signed Ctrl payload", "err", err)
		return
	}
	pld, err := scpld.PackPld()
	if err != nil {
		logger.Error("Writing IFStateReq signed Ctrl payload", "err", err)
		return
	}
	dst := &snet.Addr{
		IA:   ia,
		Host: &addr.AppAddr{L3: addr.SvcBS.Multicast(), L4: addr.NewL4UDPInfo(0)},
	}
	bsAddrs, err := rctx.Get().ResolveSVCMulti(addr.SvcBS)
	if err != nil {
		logger.Error("Resolving SVC BS multicast", "err", err)
		return
	}
	for _, addr := range bsAddrs {
		dst.NextHop = addr
		if _, err := snetConn.WriteToSCION(pld, dst); err != nil {
			logger.Error("Writing IFStateReq", "dst", dst, "err", err)
			continue
		}
		logger.Debug("Sent IFStateReq", "dst", dst, "overlayDst", addr)
	}
}
