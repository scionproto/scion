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

// This file implements the Control Plane

package rctrl

import (
	"github.com/scionproto/scion/go/border/ifstate"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

const (
	maxBufSize = 9 * 1024
)

var (
	dispPath string = reliable.DefaultDispPath
	snetConn snet.Conn
	ia       addr.IA
	logger   log.Logger
)

func Control(sRevInfoQ chan rpkt.RawSRevCallbackArgs) {
	defer log.LogPanicAndExit()
	var err error
	logger = log.New("Part", "Control")
	ctx := rctx.Get()
	ia = ctx.Conf.IA
	if err = snet.Init(ia, "", dispPath); err != nil {
		logger.Error("Initializing SNET", "err", err)
		return
	}
	ctrlAddr := ctx.Conf.Net.CtrlAddr
	pub := &snet.Addr{IA: ia, Host: ctrlAddr.IPv4.PublicAddr()}
	bind := &snet.Addr{IA: ia, Host: ctrlAddr.IPv4.BindAddr()}
	if bind.Host == nil {
		bind = nil
	}
	snetConn, err = snet.ListenSCIONWithBindSVC("udp4", pub, bind, addr.SvcNone)
	if err != nil {
		logger.Error("Listening on address", "addr", ctrlAddr, "err", err)
		return
	}
	go ifStateUpdate()
	go revInfoFwd(sRevInfoQ)
	processCtrl()
}

func processCtrl() {
	b := make(common.RawBytes, maxBufSize)
	for {
		pktLen, _, err := snetConn.ReadFromSCION(b)
		if err != nil {
			logger.Error("Reading packet", "err", err)
			continue
		}
		if err = processCtrlFromRaw(b[:pktLen]); err != nil {
			logger.Error("Processing ctrl pld", "err", err)
			continue
		}
	}
}

func processCtrlFromRaw(b common.RawBytes) error {
	scPld, err := ctrl.NewSignedPldFromRaw(b)
	if err != nil {
		return common.NewBasicError("Parsing signed ctrl pld", nil, "err", err)
	}
	cPld, err := scPld.Pld()
	if err != nil {
		return common.NewBasicError("Getting ctrl pld", nil, "err", err)
	}
	// Determine the type of SCION control payload.
	u, err := cPld.Union()
	if err != nil {
		return err
	}
	switch pld := u.(type) {
	case *path_mgmt.Pld:
		return processPathMgmtSelf(pld)
	}
	return common.NewBasicError("Unsupported control payload", nil, "type", common.TypeOf(cPld))
}

// processPathMgmtSelf handles Path Management SCION control messages.
func processPathMgmtSelf(p *path_mgmt.Pld) error {
	u, err := p.Union()
	if err != nil {
		return err
	}
	switch pld := u.(type) {
	case *path_mgmt.IFStateInfos:
		ifstate.Process(pld)
	default:
		return common.NewBasicError("Unsupported PathMgmt payload", nil,
			"type", common.TypeOf(pld))
	}
	return nil
}
