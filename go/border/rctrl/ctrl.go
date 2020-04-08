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

// This file implements the Control Plane

package rctrl

import (
	"context"

	"github.com/scionproto/scion/go/border/ifstate"
	"github.com/scionproto/scion/go/border/internal/metrics"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
)

const (
	maxBufSize = 9 * 1024
)

var (
	snetConn *snet.Conn
	ia       addr.IA
	logger   log.Logger
)

func Control(sRevInfoQ chan rpkt.RawSRevCallbackArgs, dispatcherReconnect bool) {
	var err error
	logger = log.New("Part", "Control")
	ctx := rctx.Get()
	ia = ctx.Conf.IA
	dispatcherService := reliable.NewDispatcher("")
	if dispatcherReconnect {
		dispatcherService = reconnect.NewDispatcherService(dispatcherService)
	}
	scionNetwork := snet.NewCustomNetworkWithPR(ia,
		&snet.DefaultPacketDispatcherService{
			Dispatcher: dispatcherService,
		},
	)
	ctrlAddr := ctx.Conf.BR.CtrlAddrs
	snetConn, err = scionNetwork.Listen(context.Background(), "udp", ctrlAddr.SCIONAddress,
		addr.SvcNone)
	if err != nil {
		fatal.Fatal(common.NewBasicError("Listening on address", err, "addr", ctrlAddr))
	}
	go func() {
		defer log.HandlePanic()
		ifStateUpdate()
	}()
	go func() {
		defer log.HandlePanic()
		revInfoFwd(sRevInfoQ)
	}()
	processCtrl()
}

func processCtrl() {
	b := make(common.RawBytes, maxBufSize)
	cl := metrics.ControlLabels{}
	for {
		pktLen, src, err := snetConn.ReadFrom(b)
		if err != nil {
			cl.Result = metrics.ErrRead
			metrics.Control.Reads(cl).Inc()
			fatal.Fatal(common.NewBasicError("Reading packet", err))
		}
		cl.Result = metrics.Success
		metrics.Control.Reads(cl).Inc()
		if err = processCtrlFromRaw(b[:pktLen]); err != nil {
			logger.Error("Processing ctrl pld", "src", src, "err", err)
		}
	}
}

func processCtrlFromRaw(b common.RawBytes) error {
	cl := metrics.ControlLabels{Result: metrics.ErrParse}
	scPld, err := ctrl.NewSignedPldFromRaw(b)
	if err != nil {
		metrics.Control.ProcessErrors(cl).Inc()
		return common.NewBasicError("Parsing signed ctrl pld", nil, "err", err)
	}
	cPld, err := scPld.UnsafePld()
	if err != nil {
		metrics.Control.ProcessErrors(cl).Inc()
		return common.NewBasicError("Getting ctrl pld", nil, "err", err)
	}
	// Determine the type of SCION control payload.
	u, err := cPld.Union()
	if err != nil {
		metrics.Control.ProcessErrors(cl).Inc()
		return err
	}
	switch pld := u.(type) {
	case *path_mgmt.Pld:
		err = processPathMgmtSelf(pld)
	default:
		cl.Result = metrics.ErrInvalidReq
		metrics.Control.ProcessErrors(cl).Inc()
		err = common.NewBasicError("Unsupported control payload", nil, "type", common.TypeOf(pld))
	}
	return err
}

// processPathMgmtSelf handles Path Management SCION control messages.
func processPathMgmtSelf(p *path_mgmt.Pld) error {
	cl := metrics.ControlLabels{Result: metrics.ErrParse}
	u, err := p.Union()
	if err != nil {
		metrics.Control.ProcessErrors(cl).Inc()
		return err
	}
	switch pld := u.(type) {
	case *path_mgmt.IFStateInfos:
		ifstate.Process(pld)
	default:
		cl.Result = metrics.ErrInvalidReq
		metrics.Control.ProcessErrors(cl).Inc()
		err = common.NewBasicError("Unsupported PathMgmt payload", nil, "type", common.TypeOf(pld))
	}
	return err
}
