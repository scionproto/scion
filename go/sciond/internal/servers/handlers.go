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

package servers

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/hostinfo"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
	"github.com/scionproto/scion/go/sciond/internal/fetcher"
)

const (
	// DefaultReplyTimeout is allocated to SCIOND handlers to reply back to the client.
	DefaultReplyTimeout = 2 * time.Second
	// DefaultWorkTimeout is allocated to SCIOND handlers work (e.g., network
	// traffic and crypto operations)
	DefaultWorkTimeout = 10 * time.Second
	DefaultEarlyReply  = 200 * time.Millisecond
	// DefaultServiceTTL is the TTL value for ServiceInfoReply objects,
	// expressed in seconds.
	DefaultServiceTTL uint32 = 300
)

type Handler interface {
	Handle(ctx context.Context, transport infra.Transport, src net.Addr, pld *sciond.Pld)
}

// PathRequestHandler represents the shared global state for the handling of all
// PathRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each PathRequest it receives.
type PathRequestHandler struct {
	Fetcher *fetcher.Fetcher
}

func (h *PathRequestHandler) Handle(ctx context.Context, transport infra.Transport, src net.Addr,
	pld *sciond.Pld) {

	logger := log.FromCtx(ctx)
	logger.Debug("[PathRequestHandler] Received request", "req", pld.PathReq)
	workCtx, workCancelF := context.WithTimeout(ctx, DefaultWorkTimeout)
	defer workCancelF()
	getPathsReply, err := h.Fetcher.GetPaths(workCtx, pld.PathReq, DefaultEarlyReply, logger)
	if err != nil {
		logger.Error("Unable to get paths", "err", err)
	}
	// Always reply, as the Fetcher will fill in the relevant error bits of the reply
	reply := &sciond.Pld{
		Id:        pld.Id,
		Which:     proto.SCIONDMsg_Which_pathReply,
		PathReply: getPathsReply,
	}
	b, err := proto.PackRoot(reply)
	if err != nil {
		// This is constructed locally, so it should always succeed. Otherwise,
		// it is a bug.
		panic(err)
	}
	ctx, cancelF := context.WithTimeout(ctx, DefaultReplyTimeout)
	defer cancelF()
	if err := transport.SendMsgTo(ctx, b, src); err != nil {
		logger.Warn("Unable to reply to client", "client", src, "err", err)
		return
	}
	logger.Debug("Replied with paths", "num_paths", len(getPathsReply.Entries))
	logger.Trace("Full reply", "paths", getPathsReply)
}

// ASInfoRequestHandler represents the shared global state for the handling of all
// ASInfoRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each ASInfoRequest it receives.
type ASInfoRequestHandler struct {
	TrustStore infra.TrustStore
}

func (h *ASInfoRequestHandler) Handle(ctx context.Context, transport infra.Transport, src net.Addr,
	pld *sciond.Pld) {

	logger := log.FromCtx(ctx)
	logger.Debug("[ASInfoRequestHandler] Received request", "request", &pld.AsInfoReq)
	workCtx, workCancelF := context.WithTimeout(ctx, DefaultWorkTimeout)
	defer workCancelF()
	// NOTE(scrye): Only support single-homed SCIONDs for now (returned slice
	// will at most contain one element).
	reqIA := pld.AsInfoReq.Isdas.IA()
	topo := itopo.Get()
	if reqIA.IsZero() {
		reqIA = topo.ISD_AS
	}
	asInfoReply := &sciond.ASInfoReply{}
	trcObj, err := h.TrustStore.GetValidTRC(workCtx, reqIA.I, nil)
	if err != nil {
		// FIXME(scrye): return a zero AS because the protocol doesn't
		// support errors, but we probably want to return an error here in
		// the future.
		asInfoReply.Entries = []sciond.ASInfoReplyEntry{}
	}
	if reqIA.IsZero() || reqIA.Equal(topo.ISD_AS) {
		// Requested AS is us
		asInfoReply.Entries = []sciond.ASInfoReplyEntry{
			{
				RawIsdas: topo.ISD_AS.IAInt(),
				Mtu:      uint16(topo.MTU),
				IsCore:   trcObj.CoreASes.Contains(topo.ISD_AS),
			},
		}
	} else {
		// Requested AS is not us
		asInfoReply.Entries = []sciond.ASInfoReplyEntry{
			{
				RawIsdas: reqIA.IAInt(),
				Mtu:      0,
				IsCore:   trcObj.CoreASes.Contains(reqIA),
			},
		}
	}
	reply := &sciond.Pld{
		Id:          pld.Id,
		Which:       proto.SCIONDMsg_Which_asInfoReply,
		AsInfoReply: asInfoReply,
	}
	b, err := proto.PackRoot(reply)
	if err != nil {
		panic(err)
	}
	ctx, cancelF := context.WithTimeout(ctx, DefaultReplyTimeout)
	defer cancelF()
	if err := transport.SendMsgTo(ctx, b, src); err != nil {
		logger.Warn("Unable to reply to client", "client", src, "err", err)
		return
	}
	logger.Trace("Sent reply", "asInfo", asInfoReply)
}

// IFInfoRequestHandler represents the shared global state for the handling of all
// IFInfoRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each IFInfoRequest it receives.
type IFInfoRequestHandler struct{}

func (h *IFInfoRequestHandler) Handle(ctx context.Context, transport infra.Transport, src net.Addr,
	pld *sciond.Pld) {

	logger := log.FromCtx(ctx)
	logger.Debug("[IFInfoRequestHandler] Received request", "request", &pld.IfInfoRequest)
	ifInfoRequest := pld.IfInfoRequest
	ifInfoReply := &sciond.IFInfoReply{}
	topo := itopo.Get()
	if len(ifInfoRequest.IfIDs) == 0 {
		// Reply with all the IFIDs we know
		for ifid, ifInfo := range topo.IFInfoMap {
			ifInfoReply.RawEntries = append(ifInfoReply.RawEntries, sciond.IFInfoReplyEntry{
				IfID:     ifid,
				HostInfo: hostinfo.FromTopoBRAddr(*ifInfo.InternalAddrs),
			})
		}
	} else {
		// Reply with only the IFIDs the client requested
		for _, ifid := range ifInfoRequest.IfIDs {
			ifInfo, ok := topo.IFInfoMap[ifid]
			if !ok {
				logger.Info("Received IF Info Request, but IFID not found", "ifid", ifid)
				continue
			}
			ifInfoReply.RawEntries = append(ifInfoReply.RawEntries, sciond.IFInfoReplyEntry{
				IfID:     ifid,
				HostInfo: hostinfo.FromTopoBRAddr(*ifInfo.InternalAddrs),
			})
		}
	}
	reply := &sciond.Pld{
		Id:          pld.Id,
		Which:       proto.SCIONDMsg_Which_ifInfoReply,
		IfInfoReply: ifInfoReply,
	}
	b, err := proto.PackRoot(reply)
	if err != nil {
		panic(err)
	}
	ctx, cancelF := context.WithTimeout(ctx, DefaultReplyTimeout)
	defer cancelF()
	if err := transport.SendMsgTo(ctx, b, src); err != nil {
		logger.Warn("Unable to reply to client", "client", src, "err", err)
		return
	}
	logger.Trace("Sent reply", "ifInfo", ifInfoReply)
}

// SVCInfoRequestHandler represents the shared global state for the handling of all
// SVCInfoRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each SVCInfoRequest it receives.
type SVCInfoRequestHandler struct{}

func (h *SVCInfoRequestHandler) Handle(ctx context.Context, transport infra.Transport,
	src net.Addr, pld *sciond.Pld) {

	logger := log.FromCtx(ctx)
	logger.Debug("[SVCInfoRequestHandler] Received request",
		"request", &pld.ServiceInfoRequest)
	svcInfoRequest := pld.ServiceInfoRequest
	svcInfoReply := &sciond.ServiceInfoReply{}
	topo := itopo.Get()
	for _, t := range svcInfoRequest.ServiceTypes {
		var hostInfos []hostinfo.HostInfo
		hostInfos = makeHostInfos(topo, t)
		replyEntry := sciond.ServiceInfoReplyEntry{
			ServiceType: t,
			Ttl:         DefaultServiceTTL,
			HostInfos:   hostInfos,
		}
		svcInfoReply.Entries = append(svcInfoReply.Entries, replyEntry)
	}
	reply := &sciond.Pld{
		Id:               pld.Id,
		Which:            proto.SCIONDMsg_Which_serviceInfoReply,
		ServiceInfoReply: svcInfoReply,
	}
	b, err := proto.PackRoot(reply)
	if err != nil {
		panic(err)
	}
	ctx, cancelF := context.WithTimeout(ctx, DefaultReplyTimeout)
	defer cancelF()
	if err := transport.SendMsgTo(ctx, b, src); err != nil {
		logger.Warn("Unable to reply to client", "client", src, "err", err)
		return
	}
	logger.Trace("Sent reply", "svcInfo", svcInfoReply)
}

func makeHostInfos(topo *topology.Topo, t proto.ServiceType) []hostinfo.HostInfo {
	var hostInfos []hostinfo.HostInfo
	addresses, err := topo.GetAllTopoAddrs(t)
	if err != nil {
		// FIXME(lukedirtwalker): inform client about this:
		// see https://github.com/scionproto/scion/issues/1673
		return hostInfos
	}
	for _, a := range addresses {
		hostInfos = append(hostInfos, hostinfo.FromTopoAddr(a))
	}
	return hostInfos
}

// RevNotificationHandler represents the shared global state for the handling of all
// RevNotification announcements. The SCIOND API spawns a goroutine with method Handle
// for each RevNotification it receives.
type RevNotificationHandler struct {
	RevCache   revcache.RevCache
	TrustStore infra.TrustStore
}

func (h *RevNotificationHandler) Handle(ctx context.Context, transport infra.Transport,
	src net.Addr, pld *sciond.Pld) {

	logger := log.FromCtx(ctx)
	logger.Debug("[RevNotificationHandler] Received revocation",
		"notification", pld.RevNotification)
	workCtx, workCancelF := context.WithTimeout(ctx, DefaultWorkTimeout)
	defer workCancelF()
	revNotification := pld.RevNotification
	revReply := &sciond.RevReply{}
	revInfo, err := h.verifySRevInfo(workCtx, revNotification.SRevInfo)
	if err == nil {
		_, err = h.RevCache.Insert(workCtx, revNotification.SRevInfo)
		if err != nil {
			logger.Error("Failed to insert revocations", "err", err)
		}
	}
	switch {
	case isValid(err):
		revReply.Result = sciond.RevValid
	case isStale(err):
		revReply.Result = sciond.RevStale
	case isInvalid(err):
		revReply.Result = sciond.RevInvalid
	case isUnknown(err):
		revReply.Result = sciond.RevUnknown
	default:
		panic(fmt.Sprintf("unknown error type, err = %v", err))
	}
	reply := &sciond.Pld{
		Id:       pld.Id,
		Which:    proto.SCIONDMsg_Which_revReply,
		RevReply: revReply,
	}
	b, err := proto.PackRoot(reply)
	if err != nil {
		panic(err)
	}
	ctx, cancelF := context.WithTimeout(ctx, DefaultReplyTimeout)
	defer cancelF()
	if err := transport.SendMsgTo(ctx, b, src); err != nil {
		logger.Warn("Unable to reply to client", "client", src, "err", err)
		return
	}
	logger.Trace("Sent reply", "revInfo", revInfo)
}

// verifySRevInfo first checks if the RevInfo can be extracted from sRevInfo,
// and immediately returns with an error if it cannot. Then, revocation
// verification is performed and the result is returned.
func (h *RevNotificationHandler) verifySRevInfo(ctx context.Context,
	sRevInfo *path_mgmt.SignedRevInfo) (*path_mgmt.RevInfo, error) {

	// Error out immediately if RevInfo is bad
	info, err := sRevInfo.RevInfo()
	if err != nil {
		return nil, common.NewBasicError("Unable to extract RevInfo", nil)
	}
	err = segverifier.VerifyRevInfo(ctx, h.TrustStore, nil, sRevInfo)
	return info, err
}

// isValid is a placeholder. It should return true if and only if revocation
// verification ended with an outcome of valid.
func isValid(err error) bool {
	return err == nil
}

// isStale is a placeholder. It should return true if and only if revocation
// verification ended with an outcome of stale.
func isStale(err error) bool {
	// FIXME(scrye): implement this once we have verification
	return false
}

// isInvalid is a placeholder. It should return true if and only if revocation
// verification ended with an outcome of invalid.
func isInvalid(err error) bool {
	// FIXME(scrye): implement this once we have verification
	return false
}

// isUnknown is a placeholder. It should return true if and only if revocation
// verification ended with an outcome of unknown.
func isUnknown(err error) bool {
	return err != nil
}
