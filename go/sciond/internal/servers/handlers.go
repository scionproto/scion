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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
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
	Handle(transport infra.Transport, src net.Addr, pld *sciond.Pld, logger log.Logger)
}

// PathRequestHandler represents the shared global state for the handling of all
// PathRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each PathRequest it receives.
type PathRequestHandler struct {
	Fetcher *fetcher.Fetcher
}

func (h *PathRequestHandler) Handle(transport infra.Transport, src net.Addr, pld *sciond.Pld,
	logger log.Logger) {

	logger = logger.New("pathReq", &pld.PathReq)
	logger.Debug("[SCIOND:PathRequestHandler] Received request")
	workCtx, workCancelF := context.WithTimeout(context.Background(), DefaultWorkTimeout)
	defer workCancelF()
	getPathsReply, err := h.Fetcher.GetPaths(workCtx, &pld.PathReq, DefaultEarlyReply)
	if err != nil {
		logger.Warn("[SCIOND:PathRequestHandler] Unable to get paths", "err", err)
	}
	// Always reply, as the Fetcher will fill in the relevant error bits of the reply
	reply := &sciond.Pld{
		Id:        pld.Id,
		Which:     proto.SCIONDMsg_Which_pathReply,
		PathReply: *getPathsReply,
	}
	b, err := proto.PackRoot(reply)
	if err != nil {
		// This is constructed locally, so it should always succeed. Otherwise,
		// it is a bug.
		panic(err)
	}
	ctx, cancelF := context.WithTimeout(context.Background(), DefaultReplyTimeout)
	defer cancelF()
	if err := transport.SendMsgTo(ctx, b, src); err != nil {
		logger.Warn("[SCIOND:PathRequestHandler] Unable to reply to client",
			"client", src, "err", err)
		return
	}
	logger.Debug("[SCIOND:PathRequestHandler] Replied to path request", "paths", getPathsReply)
}

// ASInfoRequestHandler represents the shared global state for the handling of all
// ASInfoRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each ASInfoRequest it receives.
type ASInfoRequestHandler struct {
	TrustStore infra.TrustStore
	Topology   *topology.Topo
}

func (h *ASInfoRequestHandler) Handle(transport infra.Transport, src net.Addr, pld *sciond.Pld,
	logger log.Logger) {

	logger = logger.New("asInfoReq", &pld.AsInfoReq)
	logger.Debug("[SCIOND:ASInfoRequestHandler] Received request")
	workCtx, workCancelF := context.WithTimeout(context.Background(), DefaultWorkTimeout)
	defer workCancelF()
	// NOTE(scrye): Only support single-homed SCIONDs for now (returned slice
	// will at most contain one element).
	reqIA := pld.AsInfoReq.Isdas.IA()
	if reqIA.IsZero() {
		reqIA = h.Topology.ISD_AS
	}
	asInfoReply := sciond.ASInfoReply{}
	trcObj, err := h.TrustStore.GetValidTRC(workCtx, reqIA.I, nil)
	if err != nil {
		// FIXME(scrye): return a zero AS because the protocol doesn't
		// support errors, but we probably want to return an error here in
		// the future.
		asInfoReply.Entries = []sciond.ASInfoReplyEntry{}
	}
	if reqIA.IsZero() || reqIA.Eq(h.Topology.ISD_AS) {
		// Requested AS is us
		asInfoReply.Entries = []sciond.ASInfoReplyEntry{
			{
				RawIsdas: h.Topology.ISD_AS.IAInt(),
				Mtu:      uint16(h.Topology.MTU),
				IsCore:   trcObj.CoreASes.Contains(h.Topology.ISD_AS),
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
	ctx, cancelF := context.WithTimeout(context.Background(), DefaultReplyTimeout)
	defer cancelF()
	if err := transport.SendMsgTo(ctx, b, src); err != nil {
		logger.Warn("Unable to reply to client", "client", src, "err", err)
		return
	}
	logger.Debug("[SCIOND:ASInfoRequestHandler] Sent reply", "asInfo", asInfoReply)
}

// IFInfoRequestHandler represents the shared global state for the handling of all
// IFInfoRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each IFInfoRequest it receives.
type IFInfoRequestHandler struct {
	Topology *topology.Topo
}

func (h *IFInfoRequestHandler) Handle(transport infra.Transport, src net.Addr, pld *sciond.Pld,
	logger log.Logger) {

	logger = logger.New("ifInfoReq", &pld.IfInfoRequest)
	logger.Debug("[SCIOND:IFInfoRequestHandler] Received request", "request", &pld.IfInfoRequest)
	ifInfoRequest := pld.IfInfoRequest
	ifInfoReply := sciond.IFInfoReply{}
	if len(ifInfoRequest.IfIDs) == 0 {
		// Reply with all the IFIDs we know
		for ifid, ifInfo := range h.Topology.IFInfoMap {
			ifInfoReply.RawEntries = append(ifInfoReply.RawEntries, sciond.IFInfoReplyEntry{
				IfID:     ifid,
				HostInfo: TopoAddrToHostInfo(h.Topology.Overlay, *ifInfo.InternalAddrs),
			})
		}
	} else {
		// Reply with only the IFIDs the client requested
		for _, ifid := range ifInfoRequest.IfIDs {
			ifInfo, ok := h.Topology.IFInfoMap[ifid]
			if !ok {
				logger.Info("Received IF Info Request, but IFID not found", "ifid", ifid)
				continue
			}
			ifInfoReply.RawEntries = append(ifInfoReply.RawEntries, sciond.IFInfoReplyEntry{
				IfID:     ifid,
				HostInfo: TopoAddrToHostInfo(h.Topology.Overlay, *ifInfo.InternalAddrs),
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
	ctx, cancelF := context.WithTimeout(context.Background(), DefaultReplyTimeout)
	defer cancelF()
	if err := transport.SendMsgTo(ctx, b, src); err != nil {
		logger.Warn("Unable to reply to client", "client", src, "err", err)
		return
	}
	logger.Debug("[SCIOND:IFInfoRequestHandler] Sent reply", "ifInfo", ifInfoReply)
}

// SVCInfoRequestHandler represents the shared global state for the handling of all
// SVCInfoRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each SVCInfoRequest it receives.
type SVCInfoRequestHandler struct {
	Topology *topology.Topo
}

func (h *SVCInfoRequestHandler) Handle(transport infra.Transport, src net.Addr, pld *sciond.Pld,
	logger log.Logger) {

	logger = logger.New("svcInfoReq", &pld.ServiceInfoRequest)
	logger.Debug("[SCIOND:SVCInfoRequestHandler] Received request")
	svcInfoRequest := pld.ServiceInfoRequest
	svcInfoReply := sciond.ServiceInfoReply{}
	for _, t := range svcInfoRequest.ServiceTypes {
		var hostInfos []sciond.HostInfo
		switch t {
		case proto.ServiceType_unset:
			// FIXME(lukedirtwalker): inform client about this:
			// see https://github.com/scionproto/scion/issues/1673
			continue
		case proto.ServiceType_bs:
			hostInfos = makeHostInfos(h.Topology.Overlay, h.Topology.BS)
		case proto.ServiceType_ps:
			hostInfos = makeHostInfos(h.Topology.Overlay, h.Topology.PS)
		case proto.ServiceType_cs:
			hostInfos = makeHostInfos(h.Topology.Overlay, h.Topology.CS)
		case proto.ServiceType_sb:
			hostInfos = makeHostInfos(h.Topology.Overlay, h.Topology.SB)
		}
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
	ctx, cancelF := context.WithTimeout(context.Background(), DefaultReplyTimeout)
	defer cancelF()
	if err := transport.SendMsgTo(ctx, b, src); err != nil {
		logger.Warn("Unable to reply to client", "client", src, "err", err)
		return
	}
	logger.Debug("[SCIOND:SVCInfoRequestHandler] Sent reply", "svcInfo", svcInfoReply)
}

func makeHostInfos(ot overlay.Type, addrMap map[string]topology.TopoAddr) []sciond.HostInfo {
	hostInfos := make([]sciond.HostInfo, 0, len(addrMap))
	for _, a := range addrMap {
		hostInfos = append(hostInfos, TopoAddrToHostInfo(ot, a))
	}
	return hostInfos
}

func TopoAddrToHostInfo(ot overlay.Type, topoAddr topology.TopoAddr) sciond.HostInfo {
	var v4Addr, v6Addr *addr.AppAddr
	var ipv4, ipv6 net.IP
	var port uint16
	if ot.IsIPv4() {
		v4Addr = topoAddr.IPv4.PublicAddr()
		if v4Addr != nil {
			// XXX(scrye): Force 4-byte representation of IPv4 addresses
			// because Python code doesn't understand Go's 16-byte format.
			ipv4 = v4Addr.L3.IP().To4()
			port = v4Addr.L4.Port()
		}
	}
	if ot.IsIPv6() {
		v6Addr = topoAddr.IPv6.PublicAddr()
		if v6Addr != nil {
			ipv6 = v6Addr.L3.IP()
			port = v6Addr.L4.Port()
		}
	}
	// XXX This assumes that Ipv4 and IPv6 use the same port!
	return sciond.HostInfo{
		Addrs: struct {
			Ipv4 []byte
			Ipv6 []byte
		}{
			Ipv4: ipv4,
			Ipv6: ipv6,
		},
		Port: port,
	}
}

// RevNotificationHandler represents the shared global state for the handling of all
// RevNotification announcements. The SCIOND API spawns a goroutine with method Handle
// for each RevNotification it receives.
type RevNotificationHandler struct {
	RevCache   revcache.RevCache
	TrustStore infra.TrustStore
}

func (h *RevNotificationHandler) Handle(transport infra.Transport, src net.Addr, pld *sciond.Pld,
	logger log.Logger) {

	logger = logger.New("revNotification", &pld.RevNotification)
	logger.Debug("[SCIOND:RevNotificationHandler] Received request")
	workCtx, workCancelF := context.WithTimeout(context.Background(), DefaultWorkTimeout)
	defer workCancelF()
	revNotification := pld.RevNotification
	revReply := sciond.RevReply{}
	revInfo, err := h.verifySRevInfo(workCtx, revNotification.SRevInfo)
	if err == nil {
		h.RevCache.Set(revcache.NewKey(revInfo.RawIsdas.IA(), common.IFIDType(revInfo.IfID)),
			revNotification.SRevInfo, revInfo.TTL())
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
	ctx, cancelF := context.WithTimeout(context.Background(), DefaultReplyTimeout)
	defer cancelF()
	if err := transport.SendMsgTo(ctx, b, src); err != nil {
		logger.Warn("Unable to reply to client", "client", src, "err", err)
		return
	}
	logger.Debug("[SCIOND:RevNotificationHandler] Sent reply", "revInfo", revInfo)
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
