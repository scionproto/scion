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
	"net"
	"sync"
	"sync/atomic"

	"github.com/scionproto/scion/go/border/brconf"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

// Ctx is the main router context structure.
type Ctx struct {
	// Conf contains the router state for this context.
	Conf *brconf.BRConf
	// HFMacPool is the pool of Hop Field MAC generation instances.
	HFMacPool *sync.Pool
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
func New(conf *brconf.BRConf) *Ctx {
	ctx := &Ctx{
		Conf:       conf,
		ExtSockOut: make(map[common.IFIDType]*Sock),
		ExtSockIn:  make(map[common.IFIDType]*Sock),
	}
	return ctx
}

// initMacPool initializes the hop field mac pool.
func (ctx *Ctx) InitMacPool() error {
	hfMacFactory, err := scrypto.HFMacFactory(ctx.Conf.MasterKeys.Key0)
	if err != nil {
		return err
	}
	// Create a pool of MAC instances.
	ctx.HFMacPool = &sync.Pool{
		New: func() interface{} {
			return hfMacFactory()
		},
	}
	return nil
}

func (ctx *Ctx) ResolveSVC(svc addr.HostSVC) ([]*net.UDPAddr, error) {
	if svc.IsMulticast() {
		return ctx.ResolveSVCMulti(svc)
	}
	resolvedAddr, err := ctx.ResolveSVCAny(svc)
	if err != nil {
		return nil, err
	}
	return []*net.UDPAddr{resolvedAddr}, nil
}

// ResolveSVCAny resolves an anycast SVC address (i.e. a single instance of a local
// infrastructure service).
func (ctx *Ctx) ResolveSVCAny(svc addr.HostSVC) (*net.UDPAddr, error) {
	return ctx.Conf.Topo.UnderlayAnycast(svc)
}

// ResolveSVCMulti resolves a multicast SVC address (i.e. one packet per machine hosting
// instances for a local infrastructure service).
func (ctx *Ctx) ResolveSVCMulti(svc addr.HostSVC) ([]*net.UDPAddr, error) {
	return ctx.Conf.Topo.UnderlayMulticast(svc)
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
