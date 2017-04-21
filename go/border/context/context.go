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

// Package context holds the current router context. The context contains a conf
// object and slices of input and output functions.

package context

import (
	"net"
	"sync"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spath"
)

// OutputObj defines a minimal interface needed to send an object over a socket.
type OutputObj interface {
	// Bytes returns the byte-string representation of the output object.
	Bytes() common.RawBytes
	// LogError can be used log errors during output.
	LogError(msg string, ctx ...interface{})
}

// OutputFunc is the type of callback required for sending a packet.
type OutputFunc func(OutputObj, *net.UDPAddr)

type InputFunc interface {
	Start()
	Stop()
}

// Context is the main context structure.
type Context struct {
	// Conf contains the router state for this context.
	Conf *conf.Conf
	// LocOutFs is a slice of functions for sending packets to local
	// destinations (i.e. within the local ISD-AS), indexed by the local
	// address id.
	LocOutFs map[int]OutputFunc
	// IntfOutFs is a slice of functions for sending packets to neighbouring
	// ISD-ASes, indexed by the interface ID of the relevant link.
	IntfOutFs map[spath.IntfID]OutputFunc
	// InputFuncs is a slice of channels to stop the corresponding input goroutines.
	InputFuncs map[string]InputFunc
}

func NewContext(conf *conf.Conf) *Context {
	ctx := &Context{
		Conf:       conf,
		LocOutFs:   make(map[int]OutputFunc),
		IntfOutFs:  make(map[spath.IntfID]OutputFunc),
		InputFuncs: make(map[string]InputFunc),
	}
	return ctx
}

// ctx is the current router context object.
var ctx *Context

// ctxLock protects access to the global context object.
var ctxLock sync.RWMutex

// GetContext returns a pointer to the current router context.
func GetContext() *Context {
	ctxLock.RLock()
	defer ctxLock.RUnlock()
	return ctx
}

// SetContext updates the current router context.
func SetContext(newCtx *Context) {
	ctxLock.Lock()
	ctx = newCtx
	ctxLock.Unlock()
}

// IA returns the ISD-AS of the router. This is shortcutted to avoid acquiring
// locks, since the ISD-AS cannot change dynamically.
func IA() *addr.ISD_AS {
	return ctx.Conf.IA
}
