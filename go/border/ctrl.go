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

// This file handles the path header (parsing/validating/updating/etc).

package main

import (
	"time"

	"github.com/scionproto/scion/go/border/ifstate"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/topology"
)

const (
	maxBufSize = 2048
)

var (
	dispPath     string        = reliable.DefaultDispPath
	initAttempts int           = 5
	initInterval time.Duration = 1 * time.Second
	snetConn     *snet.Conn
	ia           addr.IA
	logger       log.Logger
)

func initSNET(ia addr.IA, dispPath string, attempts int, sleep time.Duration) error {
	var err error
	// Initialize SCION local networking module
	for i := 0; i < attempts; i++ {
		// XXX(sgmonroy) manage snet dispatcher reconnect?
		if err = snet.Init(ia, "", dispPath); err == nil {
			break
		}
		logger.Error("Unable to initialize snet", "Retry interval", sleep, "err", err)
		time.Sleep(sleep)
	}
	return err
}

func (r *Router) Control() {
	defer log.LogPanicAndExit()
	var err error
	logger = log.New("Part", "Control")
	ctx := rctx.Get()
	ia = ctx.Conf.IA
	if err = initSNET(ia, dispPath, initAttempts, initInterval); err != nil {
		logger.Error("Initializing SNET", "err", err)
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
	}
	go ifStateUpdate()
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
		// XXX thread safe?
		ifstate.Process(pld)
	default:
		return common.NewBasicError("Unsupported PathMgmt payload", nil,
			"type", common.TypeOf(pld))
	}
	return nil
}

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
	b := make(common.RawBytes, maxBufSize)
	genIFStateReq(b)
	for range time.Tick(ifStateFreq) {
		genIFStateReq(b)
	}
}

// genIFStateReq generates an Interface State request packet to the local beacon service.
func genIFStateReq(b common.RawBytes) {
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
	pldLen, err := scpld.WritePld(b)
	if err != nil {
		logger.Error("Writting IFStateReq signed Ctrl payload", "err", err)
		return
	}
	dst := &snet.Addr{
		IA:   ia,
		Host: &addr.AppAddr{L3: addr.SvcBS.Multicast(), L4: addr.NewL4UDPInfo(0)},
	}
	// XXX(sgmonroy) at the moment, we need to implement SVC functionality here given that
	// there is no SNET support for it.
	ctx := rctx.Get()
	bsAddrs := make(map[topology.TopoAddr]struct{})
	for _, addr := range ctx.Conf.Topo.BS {
		bsAddrs[addr] = struct{}{}
	}
	l4 := addr.NewL4UDPInfo(overlay.EndhostPort)
	for ta := range bsAddrs {
		l3 := ta.IPv4.PublicAddr().L3
		if l3 == nil {
			continue
		}
		dst.NextHop, err = overlay.NewOverlayAddr(l3, l4)
		if err != nil {
			logger.Error("Failed to create overlay address", "l3", l3, "l4", l4, "err", err)
			continue
		}
		if _, err := snetConn.WriteToSCION(b[:pldLen], dst); err != nil {
			logger.Error("Writting IFStateReq", "dst", dst, "err", err)
		}
		logger.Debug("Sent IFStateReq", "dst", dst, "overlayDst", dst.NextHop)
	}
}
