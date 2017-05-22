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
	"net"
	"sync"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spath"
)

// OutputObj defines a minimal interface needed to send an object over a socket.
type OutputObj interface {
	// Bytes returns the byte-string representation of the output object.
	Bytes() common.RawBytes
	// Error can be used log errors during output.
	Error(msg string, ctx ...interface{})
}

// OutputFunc is the type of callback required for sending a packet.
type OutputFunc func(OutputObj, *net.UDPAddr)

// IOCtrl defines an interface for starting and stopping I/O goroutines.
type IOCtrl interface {
	Start()
	Stop()
}

// Ctx is the main router context structure.
type Ctx struct {
	// Conf contains the router state for this context.
	Conf *conf.Conf
	// LocOutFs is a slice of functions for sending packets to local
	// destinations (i.e. within the local ISD-AS), indexed by the local
	// address id.
	// TODO(shitz): Change this to be a slice.
	LocOutFs map[int]OutputFunc
	// IntfOutFs is a slice of functions for sending packets to neighbouring
	// ISD-ASes, indexed by the interface ID of the relevant link.
	IntfOutFs map[spath.IntfID]OutputFunc
	// IntInputFs is a slice of IOCtrl objects to stop the corresponding local
	// input goroutines.
	// TODO(shitz): Changes this to be a slice.
	LocInputFs map[int]IOCtrl
	// ExtInputFs is a slice of IOCtrl objects to stop the corresponding external
	// input goroutines.
	ExtInputFs map[spath.IntfID]IOCtrl
}

func New(conf *conf.Conf) *Ctx {
	ctx := &Ctx{
		Conf:       conf,
		LocOutFs:   make(map[int]OutputFunc),
		IntfOutFs:  make(map[spath.IntfID]OutputFunc),
		LocInputFs: make(map[int]IOCtrl),
		ExtInputFs: make(map[spath.IntfID]IOCtrl),
	}
	return ctx
}

// ctx is the current router context object.
var ctx *Ctx

// ctxLock protects access to the global context object.
var ctxLock sync.RWMutex

// Get returns a pointer to the current router context.
func Get() *Ctx {
	ctxLock.RLock()
	defer ctxLock.RUnlock()
	return ctx
}

// Set updates the current router context.
func Set(newCtx *Ctx) {
	ctxLock.Lock()
	defer ctxLock.Unlock()
	ctx = newCtx
}
