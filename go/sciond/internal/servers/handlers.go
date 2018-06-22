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
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
	"github.com/scionproto/scion/go/sciond/internal/fetcher"
)

const (
	DefaultHandlerLifetime = 10 * time.Second
	DefaultEarlyReply      = 2 * time.Second
)

// PathRequestHandler represents the shared global state for the handling of all
// PathRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each PathRequest it receives.
type PathRequestHandler struct {
	Fetcher *fetcher.Fetcher
	Logger  log.Logger
}

func (h *PathRequestHandler) Handle(transport infra.Transport, src net.Addr, pld *sciond.Pld) {
	ctx, cancelF := context.WithTimeout(context.Background(), DefaultHandlerLifetime)
	defer cancelF()
	req := pld.PathReq
	getPathsReply, err := h.Fetcher.GetPaths(ctx, &req, DefaultEarlyReply)
	if err != nil {
		h.Logger.Warn("Unable to get paths", "err", err)
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
	if err := transport.SendMsgTo(ctx, b, src); err != nil {
		h.Logger.Warn("Unable to reply to client", "client", src, "err", err)
	}
}

// ASInfoRequestHandler represents the shared global state for the handling of all
// ASInfoRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each ASInfoRequest it receives.
type ASInfoRequestHandler struct {
	TrustStore infra.TrustStore
	CoreASes   []addr.IA
	Messenger  infra.Messenger
	Topology   *topology.Topo
	Logger     log.Logger
}

func (h *ASInfoRequestHandler) Handle(transport infra.Transport, src net.Addr, pld *sciond.Pld) {
	ctx, cancelF := context.WithTimeout(context.Background(), DefaultHandlerLifetime)
	defer cancelF()
	// FIXME(scrye): Only support single-homed SCIONDs for now (returned slice
	// will at most contain one element).
	asInfoRequest := pld.AsInfoReq
	asInfoReply := sciond.ASInfoReply{}
	if asInfoRequest.Isdas.IA().IsZero() || asInfoRequest.Isdas.IA().Eq(h.Topology.ISD_AS) {
		// Requested AS is us
		asInfoReply.Entries = []sciond.ASInfoReplyEntry{
			{
				RawIsdas: h.Topology.ISD_AS.IAInt(),
				Mtu:      uint16(h.Topology.MTU),
				IsCore:   iaInSlice(h.Topology.ISD_AS, h.CoreASes),
			},
		}
	} else {
		// Requested AS is not us
		trcObj, err := h.TrustStore.GetTRC(context.TODO(), asInfoRequest.Isdas.IA().I, 0)
		if err != nil {
			// FIXME(scrye): return a zero AS because the protocol doesn't
			// support errors, but we probably want to return an error here in
			// the future.
			asInfoReply.Entries = []sciond.ASInfoReplyEntry{}
		} else {
			asInfoReply.Entries = []sciond.ASInfoReplyEntry{
				{
					RawIsdas: asInfoRequest.Isdas,
					Mtu:      0,
					IsCore:   iaInSlice(asInfoRequest.Isdas.IA(), trcObj.CoreASList()),
				},
			}
		}
	}
	reply := &sciond.Pld{
		Id:          pld.Id,
		Which:       proto.SCIONDMsg_Which_asInfoReply,
		AsInfoReply: asInfoReply,
	}
	b, err := proto.PackRoot(reply)
	if err != nil {
		log.Error("unable to serialize SCIONDMsg reply")
	}
	if err := transport.SendMsgTo(ctx, b, src); err != nil {
		h.Logger.Warn("Unable to reply to client", "client", src, "err", err)
	}
}

// IFInfoRequestHandler represents the shared global state for the handling of all
// IFInfoRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each IFInfoRequest it receives.
type IFInfoRequestHandler struct {
	Topology *topology.Topo
	Logger   log.Logger
}

func (h *IFInfoRequestHandler) Handle(transport infra.Transport, src net.Addr, pld *sciond.Pld) {
	ctx, cancelF := context.WithTimeout(context.Background(), DefaultHandlerLifetime)
	defer cancelF()
	ifInfoRequest := pld.IfInfoRequest
	ifInfoReply := sciond.IFInfoReply{}
	if len(ifInfoRequest.IfIDs) == 0 {
		// Reply with all the IFIDs we know
		for ifid, ifInfo := range h.Topology.IFInfoMap {
			ifInfoReply.RawEntries = append(ifInfoReply.RawEntries, sciond.IFInfoReplyEntry{
				IfID:     ifid,
				HostInfo: topoAddrToHostInfo(*ifInfo.InternalAddr),
			})
		}
	} else {
		// Reply with only the IFIDs the client requested
		for _, ifid := range ifInfoRequest.IfIDs {
			ifInfo, ok := h.Topology.IFInfoMap[ifid]
			if !ok {
				log.Info("Received IF Info Request, but IFID not found", "ifid", ifid)
				continue
			}
			ifInfoReply.RawEntries = append(ifInfoReply.RawEntries, sciond.IFInfoReplyEntry{
				IfID:     ifid,
				HostInfo: topoAddrToHostInfo(*ifInfo.InternalAddr),
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
		log.Error("unable to serialize SCIONDMsg reply")
	}
	if err := transport.SendMsgTo(ctx, b, src); err != nil {
		h.Logger.Warn("Unable to reply to client", "client", src, "err", err)
	}
}

// SVCInfoRequestHandler represents the shared global state for the handling of all
// SVCInfoRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each SVCInfoRequest it receives.
type SVCInfoRequestHandler struct {
	Topology *topology.Topo
	Logger   log.Logger
}

func (h *SVCInfoRequestHandler) Handle(transport infra.Transport, src net.Addr, pld *sciond.Pld) {
	ctx, cancelF := context.WithTimeout(context.Background(), DefaultHandlerLifetime)
	defer cancelF()
	svcInfoRequest := pld.ServiceInfoRequest
	svcInfoReply := sciond.ServiceInfoReply{}
	for _, t := range svcInfoRequest.ServiceTypes {
		var hostInfos []sciond.HostInfo
		switch t {
		case sciond.SvcBS:
			hostInfos = makeHostInfos(h.Topology.BS)
		case sciond.SvcPS:
			hostInfos = makeHostInfos(h.Topology.PS)
		case sciond.SvcCS:
			hostInfos = makeHostInfos(h.Topology.CS)
		case sciond.SvcBR:
			hostInfos = makeBRHostInfos(h.Topology.BR, h.Topology.IFInfoMap)
		case sciond.SvcSB:
			hostInfos = makeHostInfos(h.Topology.SB)
		}
		replyEntry := sciond.ServiceInfoReplyEntry{
			ServiceType: t,
			Ttl:         1337,
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
		log.Error("unable to serialize SCIONDMsg reply")
	}
	if err := transport.SendMsgTo(ctx, b, src); err != nil {
		h.Logger.Warn("Unable to reply to client", "client", src, "err", err)
	}
}

func makeHostInfos(addrMap map[string]topology.TopoAddr) []sciond.HostInfo {
	hostInfos := make([]sciond.HostInfo, 0, len(addrMap))
	for _, a := range addrMap {
		hostInfos = append(hostInfos, topoAddrToHostInfo(a))
	}
	return hostInfos
}

func makeBRHostInfos(brMap map[string]topology.BRInfo,
	ifInfoMap map[common.IFIDType]topology.IFInfo) []sciond.HostInfo {

	hostInfos := make([]sciond.HostInfo, 0, len(brMap))
	for _, brInfo := range brMap {
		// One IFID is enough to find the unique internal address. Panic if no
		// IFIDs exist.
		ifid := brInfo.IFIDs[0]
		hostInfos = append(hostInfos, topoAddrToHostInfo(*ifInfoMap[ifid].InternalAddr))
	}
	return hostInfos
}

func topoAddrToHostInfo(topoAddr topology.TopoAddr) sciond.HostInfo {
	// FIXME(scrye): also add support for IPv6
	return sciond.HostInfo{
		Addrs: struct {
			Ipv4 []byte
			Ipv6 []byte
		}{
			Ipv4: topoAddr.IPv4.PublicAddr(),
		},
		Port: uint16(topoAddr.IPv4.PublicL4Port()),
	}
}

// RevNotificationHandler represents the shared global state for the handling of all
// RevNotification announcements. The SCIOND API spawns a goroutine with method Handle
// for each RevNotification it receives.
type RevNotificationHandler struct {
	RevCache *fetcher.RevCache
	Logger   log.Logger
}

func (h *RevNotificationHandler) Handle(transport infra.Transport, src net.Addr, pld *sciond.Pld) {
	ctx, cancelF := context.WithTimeout(context.Background(), DefaultHandlerLifetime)
	defer cancelF()
	revNotification := pld.RevNotification
	revReply := sciond.RevReply{}
	revInfo, err := h.verifySRevInfo(ctx, revNotification.SRevInfo)
	if err == nil {
		h.RevCache.Add(revInfo.RawIsdas.IA(), common.IFIDType(revInfo.IfID),
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
		log.Error("unable to serialize SCIONDMsg reply")
	}
	if err := transport.SendMsgTo(ctx, b, src); err != nil {
		h.Logger.Warn("Unable to reply to client", "client", src, "err", err)
	}
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
	// FIXME(scrye): pass in trail here
	err = segverifier.VerifyRevInfo(ctx, sRevInfo, []addr.ISD{})
	return info, err
}

// isValid is a placeholder. It should return true if and only if revocation
// verification ended with an outcome of valid.
func isValid(err error) bool {
	// FIXME(scrye): implement this once we have verification
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
	// FIXME(scrye): implement this once we have verification
	return err != nil
}

func iaInSlice(ia addr.IA, s []addr.IA) bool {
	for _, otherIA := range s {
		if otherIA.Eq(ia) {
			return true
		}
	}
	return false
}
