// Copyright 2016 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package main

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/border/brconf"
	"github.com/scionproto/scion/go/border/netconf"
	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/overlay/conn"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/ringbuf"
)

const PosixSock brconf.SockType = "posix"

func init() {
	registeredLocSockOps[PosixSock] = posixLoc{}
	registeredExtSockOps[PosixSock] = posixExt{}
}

var _ locSockOps = posixLoc{}

type posixLoc struct{}

// Setup configures a local POSIX(/BSD) socket.
func (p posixLoc) Setup(r *Router, ctx *rctx.Ctx, labels prometheus.Labels,
	oldCtx *rctx.Ctx) error {

	// No old context. This happens during startup of the router.
	if oldCtx != nil {
		if ctx.Conf.Net.LocAddr.Equal(oldCtx.Conf.Net.LocAddr) {
			log.Debug("No change detected for local socket.")
			// Nothing changed. Copy I/O functions from old context.
			ctx.LocSockIn = oldCtx.LocSockIn
			ctx.LocSockOut = oldCtx.LocSockOut
			return nil
		}
	}
	// New bind address. Configure Posix I/O.
	// Get Bind address if set, Public otherwise
	bind := ctx.Conf.Net.LocAddr.BindOrPublicOverlay(ctx.Conf.Topo.Overlay)
	if err := p.addSock(r, ctx, bind, labels); err != nil {
		return err
	}
	return nil
}

func (p posixLoc) addSock(r *Router, ctx *rctx.Ctx, bind *overlay.OverlayAddr,
	labels prometheus.Labels) error {

	log.Debug("Setting up new local socket.", "bind", bind)
	// Listen on the socket.
	over, err := conn.New(bind, nil, labels)
	if err != nil {
		return common.NewBasicError("Unable to listen on local socket", err, "bind", bind)
	}
	// Setup input goroutine.
	ctx.LocSockIn = rctx.NewSock(ringbuf.New(64, nil, "locIn", mkRingLabels(labels)),
		over, rcmn.DirLocal, 0, labels, r.posixInput, r.handleSock, PosixSock)
	ctx.LocSockOut = rctx.NewSock(ringbuf.New(64, nil, "locOut", mkRingLabels(labels)),
		over, rcmn.DirLocal, 0, labels, nil, r.posixOutput, PosixSock)
	log.Debug("Done setting up new local socket.", "conn", over.LocalAddr())
	return nil
}

var _ extSockOps = posixExt{}

type posixExt posixLoc

// Setup configures a POSIX(/BSD) interface socket.
func (p posixExt) Setup(r *Router, ctx *rctx.Ctx, intf *netconf.Interface,
	labels prometheus.Labels, oldCtx *rctx.Ctx) error {

	// No old context. This happens during startup of the router.
	if oldCtx == nil {
		if err := p.addIntf(r, ctx, intf, labels); err != nil {
			return err
		}
		return nil
	}
	if oldIntf, ok := oldCtx.Conf.Net.IFs[intf.Id]; !ok {
		// New interface got added. Configure Posix I/O.
		if err := p.addIntf(r, ctx, intf, labels); err != nil {
			return err
		}
	} else if interfaceChanged(intf, oldIntf) {
		log.Debug("Existing interface changed.", "old", oldIntf, "new", intf)
		// Configure new Posix I/O.
		if err := p.addIntf(r, ctx, intf, labels); err != nil {
			return err
		}
		// An existing interface has changed.
		// Stop old input goroutine.
		oldCtx.ExtSockIn[intf.Id].Stop()
		oldCtx.ExtSockOut[intf.Id].Stop()
	} else {
		log.Debug("No change detected for external socket.", "conn",
			intf.IFAddr.BindOrPublicOverlay(ctx.Conf.Topo.Overlay))
		// Nothing changed. Copy I/O functions from old context.
		ctx.ExtSockIn[intf.Id] = oldCtx.ExtSockIn[intf.Id]
		ctx.ExtSockOut[intf.Id] = oldCtx.ExtSockOut[intf.Id]
	}
	return nil
}

func (p posixExt) addIntf(r *Router, ctx *rctx.Ctx, intf *netconf.Interface,
	labels prometheus.Labels) error {

	// Connect to remote address.
	log.Debug("Setting up new external socket.", "intf", intf)
	bind := intf.IFAddr.BindOrPublicOverlay(intf.IFAddr.Overlay)
	c, err := conn.New(bind, intf.RemoteAddr, labels)
	if err != nil {
		return common.NewBasicError("Unable to listen on external socket", err)
	}
	// Setup input goroutine.
	ctx.ExtSockIn[intf.Id] = rctx.NewSock(ringbuf.New(64, nil, "extIn", mkRingLabels(labels)),
		c, rcmn.DirExternal, intf.Id, labels, r.posixInput, r.handleSock, PosixSock)
	ctx.ExtSockOut[intf.Id] = rctx.NewSock(ringbuf.New(64, nil, "extOut", mkRingLabels(labels)),
		c, rcmn.DirExternal, intf.Id, labels, nil, r.posixOutput, PosixSock)
	log.Debug("Done setting up new external socket.", "intf", intf)
	return nil
}

// interfaceChanged returns true if a new input goroutine is needed for the
// corresponding interface.
func interfaceChanged(newIntf *netconf.Interface, oldIntf *netconf.Interface) bool {
	return (newIntf.Id != oldIntf.Id ||
		!newIntf.IFAddr.Equal(oldIntf.IFAddr) ||
		!newIntf.RemoteAddr.Eq(oldIntf.RemoteAddr))
}

// Create a set of labels for ringbuf with `sock` renamed to `ringId`.
func mkRingLabels(labels prometheus.Labels) prometheus.Labels {
	ringLabels := prom.CopyLabels(labels)
	ringLabels["ringId"] = labels["sock"]
	delete(ringLabels, "sock")
	return ringLabels
}
