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
	"github.com/scionproto/scion/go/border/internal/metrics"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

// RevInfoFwd takes RevInfos, and forwards them to the local Beacon Service
// (BS) and Path Service (PS).
func revInfoFwd(revInfoQ chan rpkt.RawSRevCallbackArgs) {
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
		logger.Debug("Forwarding revocation", "revInfo", revInfo.String(), "targets", args.Addrs)
		for _, svcAddr := range args.Addrs {
			fwdRevInfo(args.SignedRevInfo, svcAddr)
		}
	}
}

// fwdRevInfo forwards RevInfo payloads to a designated local host.
func fwdRevInfo(sRevInfo *path_mgmt.SignedRevInfo, dstHost addr.HostSVC) {
	cl := metrics.SentRevInfoLabels{
		Result: metrics.ErrProcess,
		SVC:    dstHost.BaseString(),
	}
	ctx := rctx.Get()
	cpld, err := ctrl.NewPathMgmtPld(sRevInfo, nil, nil)
	if err != nil {
		metrics.Control.SentRevInfos(cl).Inc()
		log.Error("Error generating RevInfo Ctrl payload", "err", err)
		return
	}
	scpld, err := cpld.SignedPld(infra.NullSigner)
	if err != nil {
		metrics.Control.SentRevInfos(cl).Inc()
		log.Error("Error generating RevInfo signed Ctrl payload", "err", err)
		return
	}
	pld, err := scpld.PackPld()
	if err != nil {
		metrics.Control.SentRevInfos(cl).Inc()
		logger.Error("Writing RevInfo signed Ctrl payload", "err", err)
		return
	}
	dst := &snet.SVCAddr{IA: ia, SVC: dstHost}
	dst.NextHop, err = ctx.ResolveSVCAny(dstHost)
	if err != nil {
		cl.Result = metrics.ErrResolveSVC
		metrics.Control.SentRevInfos(cl).Inc()
		logger.Error("Resolving SVC anycast", "err", err, "addr", dst)
		return
	}
	if _, err := snetConn.WriteTo(pld, dst); err != nil {
		metrics.Control.SentRevInfos(cl).Inc()
		logger.Error("Writing RevInfo", "dst", dst, "err", err)
		return
	}
	cl.Result = metrics.Success
	metrics.Control.SentRevInfos(cl).Inc()
	logger.Debug("Sent RevInfo", "dst", dst, "underlayDst", dst.NextHop)
}
