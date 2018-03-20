// Copyright 2017 ETH Zurich
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
	"sync/atomic"

	"github.com/scionproto/scion/go/border/conf"
	"github.com/scionproto/scion/go/lib/common"
)

// Ctx is the main router context structure.
type Ctx struct {
	// Conf contains the router state for this context.
	Conf *conf.Conf
	// LockSockIn is a slice of Sock's for receiving packets from the local AS,
	// indexed by the local address index.
	LocSockIn []*Sock
	// LocSockOut is a slice of Sock's for sending packets to the local AS,
	// indexed by the local address index.
	LocSockOut []*Sock
	// ExtSockIn is a map of Sock's for receiving packets from neighbouring
	// ASes, keyed by the interface ID of the relevant link.
	ExtSockIn map[common.IFIDType]*Sock
	// ExtSockOut is a map of Sock's for sending packets to neighbouring ASes,
	// keyed by the interface ID of the relevant link.
	ExtSockOut map[common.IFIDType]*Sock
}

// New returns a new Ctx instance.
func New(conf *conf.Conf, intAddrCnt int) *Ctx {
	ctx := &Ctx{
		Conf:       conf,
		LocSockOut: make([]*Sock, intAddrCnt),
		ExtSockOut: make(map[common.IFIDType]*Sock),
		LocSockIn:  make([]*Sock, intAddrCnt),
		ExtSockIn:  make(map[common.IFIDType]*Sock),
	}
	return ctx
}

// ctx is the current router context object.
var ctx atomic.Value

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
