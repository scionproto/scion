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
	"time"

	"github.com/scionproto/scion/go/border/internal/metrics"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
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
	if err := genIFStateReq(); err != nil {
		logger.Error(err.Error())
	}
	for range time.Tick(ifStateFreq) {
		if err := genIFStateReq(); err != nil {
			logger.Error(err.Error())
		}
	}
}

// genIFStateReq generates an Interface State request packet to the local beacon service.
func genIFStateReq() error {
	metrics.Control.IFStateTick().Inc()
	cl := metrics.ControlLabels{
		Result: metrics.ErrProcess,
	}
	cpld, err := ctrl.NewPathMgmtPld(&path_mgmt.IFStateReq{}, nil, nil)
	if err != nil {
		metrics.Control.SentIFStateReq(cl).Inc()
		return common.NewBasicError("Generating IFStateReq Ctrl payload", err)
	}
	scpld, err := cpld.SignedPld(infra.NullSigner)
	if err != nil {
		metrics.Control.SentIFStateReq(cl).Inc()
		return common.NewBasicError("Generating IFStateReq signed Ctrl payload", err)
	}
	pld, err := scpld.PackPld()
	if err != nil {
		metrics.Control.SentIFStateReq(cl).Inc()
		return common.NewBasicError("Writing IFStateReq signed Ctrl payload", err)
	}
	bsAddrs, err := rctx.Get().ResolveSVCMulti(addr.SvcBS)
	if err != nil {
		cl.Result = metrics.ErrResolveSVC
		metrics.Control.SentIFStateReq(cl).Inc()
		return common.NewBasicError("Resolving SVC BS multicast", err)
	}

	var errors common.MultiError
	for _, a := range bsAddrs {
		dst := &snet.SVCAddr{IA: ia, NextHop: a, SVC: addr.SvcBS.Multicast()}
		if _, err := snetConn.WriteTo(pld, dst); err != nil {
			cl.Result = metrics.ErrWrite
			metrics.Control.SentIFStateReq(cl).Inc()
			errors = append(errors, common.NewBasicError("Writing IFStateReq", err, "dst", dst))
			continue
		}
		logger.Debug("Sent IFStateReq", "dst", dst, "underlayDst", a)
		cl.Result = metrics.Success
		metrics.Control.SentIFStateReq(cl).Inc()
	}
	return errors.ToError()
}
