// Copyright 2017 ETH Zurich
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

// Package rctx holds the current router context. The context contains a conf
// object and slices of input and output functions.
package rctx

import (
	"math/rand"
	"sync/atomic"

	"github.com/scionproto/scion/go/border/conf"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/topology"
)

// Ctx is the main router context structure.
type Ctx struct {
	// Conf contains the router state for this context.
	Conf *conf.Conf
	// LockSockIn is a Sock for receiving packets from the local AS,
	LocSockIn *Sock
	// LocSockOut is a Sock for sending packets to the local AS,
	LocSockOut *Sock
	// ExtSockIn is a map of Sock's for receiving packets from neighbouring
	// ASes, keyed by the interface ID of the relevant link.
	ExtSockIn map[common.IFIDType]*Sock
	// ExtSockOut is a map of Sock's for sending packets to neighbouring ASes,
	// keyed by the interface ID of the relevant link.
	ExtSockOut map[common.IFIDType]*Sock
}

// ctx is the current router context object.
var ctx atomic.Value

// New returns a new Ctx instance.
func New(conf *conf.Conf) *Ctx {
	ctx := &Ctx{
		Conf:       conf,
		ExtSockOut: make(map[common.IFIDType]*Sock),
		ExtSockIn:  make(map[common.IFIDType]*Sock),
	}
	return ctx
}

func (ctx *Ctx) ResolveSVC(svc addr.HostSVC) ([]*overlay.OverlayAddr, error) {
	if svc.IsMulticast() {
		return ctx.ResolveSVCMulti(svc)
	}
	resolvedAddr, err := ctx.ResolveSVCAny(svc)
	if err != nil {
		return nil, err
	}
	return []*overlay.OverlayAddr{resolvedAddr}, nil
}

// ResolveSVCAny resolves an anycast SVC address (i.e. a single instance of a local
// infrastructure service).
func (ctx *Ctx) ResolveSVCAny(svc addr.HostSVC) (*overlay.OverlayAddr, error) {
	names, elemMap, err := ctx.GetSVCNamesMap(svc)
	if err != nil {
		return nil, err
	}
	// XXX(kormat): just pick one randomly. TCP will remove the need to have
	// consistent selection for a given source.
	name := names[rand.Intn(len(names))]
	elem := elemMap[name]
	return elem.OverlayAddr(ctx.Conf.Topo.Overlay), nil
}

// ResolveSVCMulti resovles a multicast SVC address (i.e. one packet per machine hosting
// instances for a local infrastructure service).
func (ctx *Ctx) ResolveSVCMulti(svc addr.HostSVC) ([]*overlay.OverlayAddr, error) {
	_, elemMap, err := ctx.GetSVCNamesMap(svc)
	if err != nil {
		return nil, err
	}
	// Only send once per IP:OverlayPort combination. Adding the overlay port
	// allows this to work even when multiple instances are NAT'd to the same
	// IP address.
	uniqAddrs := make(map[string]struct{})
	overAddrs := []*overlay.OverlayAddr{}
	ot := ctx.Conf.Topo.Overlay
	for _, elem := range elemMap {
		overAddr := elem.OverlayAddr(ot)
		addrStr := overAddr.String()
		if _, ok := uniqAddrs[addrStr]; ok {
			continue
		}
		uniqAddrs[addrStr] = struct{}{}
		overAddrs = append(overAddrs, overAddr)
	}
	return overAddrs, nil
}

// GetSVCNamesMap returns the slice of instance names and addresses for a given SVC address.
func (ctx *Ctx) GetSVCNamesMap(svc addr.HostSVC) ([]string,
	map[string]topology.TopoAddr, error) {

	t := ctx.Conf.Topo
	var names []string
	var elemMap map[string]topology.TopoAddr
	switch svc.Base() {
	case addr.SvcBS:
		names, elemMap = t.BSNames, t.BS
	case addr.SvcPS:
		names, elemMap = t.PSNames, t.PS
	case addr.SvcCS:
		names, elemMap = t.CSNames, t.CS
	case addr.SvcSB:
		names, elemMap = t.SBNames, t.SB
	case addr.SvcSIG:
		names, elemMap = t.SIGNames, t.SIG
	default:
		return nil, nil, common.NewBasicError("Unsupported SVC address",
			scmp.NewError(scmp.C_Routing, scmp.T_R_BadHost, nil, nil), "svc", svc)
	}
	if len(elemMap) == 0 {
		return nil, nil, common.NewBasicError("No instances found for SVC address",
			scmp.NewError(scmp.C_Routing, scmp.T_R_UnreachHost, nil, nil), "svc", svc)
	}
	return names, elemMap, nil
}

// Get returns a pointer to the current router context.
func Get() *Ctx {
	c := ctx.Load()
	if c != nil {
		return c.(*Ctx)
	}
	return nil
}

// Set updates the current router context.
func Set(newCtx *Ctx) {
	ctx.Store(newCtx)
}
