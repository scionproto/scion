// Copyright 2016 ETH Zurich
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

// This file handles the router setup, from getting the config loaded, to
// configuring the network interfaces, and starting the input goroutines.
// Support for POSIX(/BSD) sockets is included here, with hooks to allow other
// network stacks to be loaded instead/additionally.

package main

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/syndtr/gocapability/capability"

	"github.com/scionproto/scion/go/border/brconf"
	"github.com/scionproto/scion/go/border/ifstate"
	"github.com/scionproto/scion/go/border/netconf"
	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/overlay/conn"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/ringbuf"
)

type setupNetHook func(r *Router, ctx *rctx.Ctx,
	oldCtx *rctx.Ctx) (rpkt.HookResult, error)
type setupAddLocalHook func(r *Router, ctx *rctx.Ctx, labels prometheus.Labels,
	oldCtx *rctx.Ctx) (rpkt.HookResult, error)
type setupAddExtHook func(r *Router, ctx *rctx.Ctx, intf *netconf.Interface,
	labels prometheus.Labels, oldCtx *rctx.Ctx) (rpkt.HookResult, error)

// Setup hooks enables the network stack to be modular. Any network stack that
// wants to be included defines its own init function which adds hooks to these
// hook slices. See setup-hsr.go for an example.
var setupNetStartHooks []setupNetHook
var setupAddLocalHooks []setupAddLocalHook
var setupAddExtHooks []setupAddExtHook
var setupNetFinishHooks []setupNetHook

type rollbackLocalHook func(r *Router, ctx *rctx.Ctx, oldCtx *rctx.Ctx) rpkt.HookResult
type rollbackExtHook func(r *Router, ctx *rctx.Ctx, intf *netconf.Interface,
	oldCtx *rctx.Ctx) rpkt.HookResult

// Rollback hooks are called to undo the changes that have happened during setupNet
// with a new context.
var rollbackLocalHooks []rollbackLocalHook
var rollbackExtHooks []rollbackExtHook

type teardownHook func(r *Router, ctx *rctx.Ctx, oldCtx *rctx.Ctx) rpkt.HookResult

// Teardown hooks are called to teardown the net part of an old context after
// the new context has been successfully loaded.
var teardownLocalHooks []teardownHook
var teardownExtHooks []teardownHook

// addPosixHooks adds the default posix hooks.
func addPosixHooks() {
	setupNetStartHooks = append(setupNetStartHooks, setupVerifyNoAddrTakeover)
	setupAddLocalHooks = append(setupAddLocalHooks, setupPosixAddLocal)
	setupAddExtHooks = append(setupAddExtHooks, setupPosixAddExt)
	rollbackLocalHooks = append(rollbackLocalHooks, rollbackPosixAddLocal)
	rollbackExtHooks = append(rollbackExtHooks, rollbackPosixAddExt)
	teardownLocalHooks = append(teardownLocalHooks, teardownPosixLocal)
	teardownExtHooks = append(teardownExtHooks, teardownPosixExt)
}

// newConn is the function used to setup a connection. Per default, `conn.New` is used.
var newConn = conn.New

// setup creates the router's channels and map, sets up the rpkt package, and
// sets up a new router context. This function can only be called once during startup.
func (r *Router) setup() error {
	r.freePkts = ringbuf.New(1024, func() interface{} {
		return rpkt.NewRtrPkt()
	}, "free", prometheus.Labels{"ringId": "freePkts"})
	r.sRevInfoQ = make(chan rpkt.RawSRevCallbackArgs, 16)
	r.pktErrorQ = make(chan pktErrorArgs, 16)

	// Configure the rpkt package with the callbacks it needs.
	rpkt.Init(r.RawSRevCallback)

	// Add default posix hooks. If there are other hooks, they should install
	// themselves via init(), so they appear before the posix ones.
	addPosixHooks()

	// Load config.
	var err error
	var conf *brconf.Conf
	if conf, err = r.loadNewConfig(); err != nil {
		return err
	}
	// Setup new context.
	if err = r.setupNewContext(conf); err != nil {
		return err
	}
	// Clear capabilities after setting up the network. Capabilities are currently
	// only needed by the HSR for which the router never reconfigures the network.
	if err = r.clearCapabilities(); err != nil {
		return err
	}
	config.Metrics.StartPrometheus()
	return nil
}

// clearCapabilities drops unnecessary capabilities after startup
func (r *Router) clearCapabilities() error {
	caps, err := capability.NewPid(0)
	if err != nil {
		return common.NewBasicError("Error retrieving capabilities", err)
	}
	log.Debug("Startup capabilities", "caps", caps)
	caps.Clear(capability.CAPS)
	caps.Apply(capability.CAPS)
	caps.Load()
	log.Debug("Cleared capabilities", "caps", caps)
	return nil
}

// loadNewConfig loads a new brconf.Conf object from the configuration file.
func (r *Router) loadNewConfig() (*brconf.Conf, error) {
	var config *brconf.Conf
	var err error
	if config, err = brconf.Load(r.Id, r.confDir); err != nil {
		return nil, common.NewBasicError("Failed to load topology config", err, "dir", r.confDir)
	}
	log.Debug("Topology and AS config loaded", "IA", config.IA, "IfIDs", config.BR,
		"dir", r.confDir)
	return config, nil
}

// setupNewContext sets up a new router context.
func (r *Router) setupNewContext(config *brconf.Conf) error {
	log.Debug("====> Setting up new context")
	defer log.Debug("====> Done setting up new context")
	oldCtx := rctx.Get()
	ctx := rctx.New(config)
	if err := r.setupNet(ctx, oldCtx); err != nil {
		r.rollbackNet(ctx, oldCtx)
		return err
	}
	rctx.Set(ctx)
	startSocks(ctx)
	r.teardownOldNet(ctx, oldCtx)
	return nil
}

// startSocks starts all sockets for the given context.
func startSocks(ctx *rctx.Ctx) {
	// Start local input functions.
	ctx.LocSockIn.Start()
	// Start local output functions.
	ctx.LocSockOut.Start()
	// Start external input functions.
	for _, s := range ctx.ExtSockIn {
		s.Start()
	}
	// Start external output functions.
	for _, s := range ctx.ExtSockOut {
		s.Start()
	}
}

// setupNet configures networking for the router, using any setup hooks that
// have been registered. If an old context is provided, setupNet reconfigures
// networking, e.g., starting/stopping new/old input routines if necessary.
func (r *Router) setupNet(ctx *rctx.Ctx, oldCtx *rctx.Ctx) error {
	// Run startup hooks, if any.
	for _, f := range setupNetStartHooks {
		ret, err := f(r, ctx, oldCtx)
		switch {
		case err != nil:
			return err
		case ret == rpkt.HookContinue:
			continue
		case ret == rpkt.HookFinish:
			break
		}
	}
	// Iterate over local addresses, configuring them via provided hooks.
	labels := prometheus.Labels{"sock": "loc"}
	for _, f := range setupAddLocalHooks {
		ret, err := f(r, ctx, labels, oldCtx)
		switch {
		case err != nil:
			return err
		case ret == rpkt.HookContinue:
			continue
		case ret == rpkt.HookFinish:
			break
		}
	}
	// Iterate over interfaces, configuring them via provided hooks.
	for _, intf := range ctx.Conf.Net.IFs {
		labels := prometheus.Labels{"sock": fmt.Sprintf("intf:%d", intf.Id)}
	InnerLoop:
		for _, f := range setupAddExtHooks {
			ret, err := f(r, ctx, intf, labels, oldCtx)
			switch {
			case err != nil:
				return err
			case ret == rpkt.HookContinue:
				continue
			case ret == rpkt.HookFinish:
				// Break out of switch statement and inner loop.
				break InnerLoop
			}
		}
	}
	// Run finish hooks, if any.
	for _, f := range setupNetFinishHooks {
		ret, err := f(r, ctx, oldCtx)
		switch {
		case err != nil:
			return err
		case ret == rpkt.HookContinue:
			continue
		case ret == rpkt.HookFinish:
			break
		}
	}
	return nil
}

// rollbackNet rolls back the changes of a failed call to setupNet.
func (r *Router) rollbackNet(ctx *rctx.Ctx, oldCtx *rctx.Ctx) {
	for _, intf := range ctx.Conf.Net.IFs {
	InnerLoop:
		for _, f := range rollbackExtHooks {
			ret := f(r, ctx, intf, oldCtx)
			switch {
			case ret == rpkt.HookContinue:
				continue
			case ret == rpkt.HookFinish:
				break InnerLoop
			}
		}
	}
	for _, f := range rollbackLocalHooks {
		ret := f(r, ctx, oldCtx)
		switch {
		case ret == rpkt.HookContinue:
			continue
		case ret == rpkt.HookFinish:
			break
		}
	}
}

// teardownOldNet tearsdown the no longer used parts of the old context.
func (r *Router) teardownOldNet(ctx *rctx.Ctx, oldCtx *rctx.Ctx) {
	rangeTeardownHooks(r, ctx, oldCtx, teardownLocalHooks)
	rangeTeardownHooks(r, ctx, oldCtx, teardownExtHooks)
	// Clean-up interface state infos that are not present anymore.
	if oldCtx != nil {
		for ifID := range oldCtx.Conf.Topo.IFInfoMap {
			if _, ok := ctx.Conf.Topo.IFInfoMap[ifID]; !ok {
				ifstate.DeleteState(ifID)
			}
		}
	}
}

func rangeTeardownHooks(r *Router, ctx *rctx.Ctx, oldCtx *rctx.Ctx, hooks []teardownHook) {
	for _, f := range hooks {
		ret := f(r, ctx, oldCtx)
		switch {
		case ret == rpkt.HookContinue:
			continue
		case ret == rpkt.HookFinish:
			break
		}
	}
}

// setupPosixAddLocal configures a local POSIX(/BSD) socket.
func setupPosixAddLocal(r *Router, ctx *rctx.Ctx, labels prometheus.Labels,
	oldCtx *rctx.Ctx) (rpkt.HookResult, error) {
	// No old context. This happens during startup of the router.
	if oldCtx != nil {
		if ctx.Conf.Net.LocAddr.Equal(oldCtx.Conf.Net.LocAddr) {
			log.Debug("No change detected for local socket.")
			// Nothing changed. Copy I/O functions from old context.
			ctx.LocSockIn = oldCtx.LocSockIn
			ctx.LocSockOut = oldCtx.LocSockOut
			return rpkt.HookFinish, nil
		}
	}
	// New bind address. Configure Posix I/O.
	// Get Bind address if set, Public otherwise
	bind := ctx.Conf.Net.LocAddr.BindOrPublicOverlay(ctx.Conf.Topo.Overlay)
	if err := addPosixLocal(r, ctx, bind, labels); err != nil {
		return rpkt.HookError, err
	}
	return rpkt.HookFinish, nil
}

func addPosixLocal(r *Router, ctx *rctx.Ctx, bind *overlay.OverlayAddr,
	labels prometheus.Labels) error {
	log.Debug("Setting up new local socket.")
	// Listen on the socket.
	over, err := newConn(bind, nil, labels)
	if err != nil {
		return common.NewBasicError("Unable to listen on local socket", err)
	}
	// Setup input goroutine.
	ctx.LocSockIn = rctx.NewSock(ringbuf.New(64, nil, "locIn", mkRingLabels(labels)),
		over, rcmn.DirLocal, 0, labels, r.posixInput, r.handleSock)
	ctx.LocSockOut = rctx.NewSock(ringbuf.New(64, nil, "locOut", mkRingLabels(labels)),
		over, rcmn.DirLocal, 0, labels, nil, r.posixOutput)
	log.Debug("Done setting up new local socket.", "conn", over.LocalAddr())
	return nil
}

// rollbackPosixAddLocal undoes the changes made by setupPosixAddLocal.
func rollbackPosixAddLocal(r *Router, ctx *rctx.Ctx, oldCtx *rctx.Ctx) rpkt.HookResult {
	// The socket has been reused from old context and should not be closed.
	if oldCtx != nil && ctx.Conf.Net.LocAddr.Equal(oldCtx.Conf.Net.LocAddr) {
		return rpkt.HookFinish
	}
	if ctx.LocSockIn != nil {
		log.Debug("Rolling back local socket", "conn", ctx.LocSockIn.Conn.LocalAddr())
	}
	stopSock(ctx.LocSockIn)
	stopSock(ctx.LocSockOut)
	return rpkt.HookFinish
}

// setupPosixAddExt configures a POSIX(/BSD) interface socket.
func setupPosixAddExt(r *Router, ctx *rctx.Ctx, intf *netconf.Interface,
	labels prometheus.Labels, oldCtx *rctx.Ctx) (rpkt.HookResult, error) {
	// No old context. This happens during startup of the router.
	if oldCtx == nil {
		if err := addPosixIntf(r, ctx, intf, labels); err != nil {
			return rpkt.HookError, err
		}
		return rpkt.HookFinish, nil
	}
	if oldIntf, ok := oldCtx.Conf.Net.IFs[intf.Id]; ok {
		// Reuse socket if the interface has not changed.
		if !interfaceChanged(intf, oldIntf) {
			log.Debug("No change detected for external socket.", "conn",
				intf.IFAddr.BindOrPublicOverlay(ctx.Conf.Topo.Overlay))
			ctx.ExtSockIn[intf.Id] = oldCtx.ExtSockIn[intf.Id]
			ctx.ExtSockOut[intf.Id] = oldCtx.ExtSockOut[intf.Id]
			return rpkt.HookFinish, nil
		}
		// Release the socket in order to successfully bind afterwards.
		// FIXME(roosd): After switching to go 1.11+, this can be avoided using SO_REUSEPORT.
		if intf.IFAddr.Equal(oldIntf.IFAddr) {
			log.Debug("Closing existing external socket to free addr", "old", oldIntf, "new", intf)
			stopSock(oldCtx.ExtSockIn[intf.Id])
			stopSock(oldCtx.ExtSockOut[intf.Id])
		}
		log.Debug("Existing interface changed", "old", oldIntf, "new", intf)
	}
	if err := addPosixIntf(r, ctx, intf, labels); err != nil {
		return rpkt.HookError, err
	}
	return rpkt.HookFinish, nil
}

// interfaceChanged returns true if a new input goroutine is needed for the
// corresponding interface.
func interfaceChanged(newIntf *netconf.Interface, oldIntf *netconf.Interface) bool {
	return (newIntf.Id != oldIntf.Id ||
		!newIntf.IFAddr.Equal(oldIntf.IFAddr) ||
		!newIntf.RemoteAddr.Eq(oldIntf.RemoteAddr))
}

func addPosixIntf(r *Router, ctx *rctx.Ctx, intf *netconf.Interface,
	labels prometheus.Labels) error {
	// Connect to remote address.
	log.Debug("Setting up new external socket.", "intf", intf)
	bind := intf.IFAddr.BindOrPublicOverlay(intf.IFAddr.Overlay)
	c, err := newConn(bind, intf.RemoteAddr, labels)
	if err != nil {
		return common.NewBasicError("Unable to listen on external socket", err)
	}
	// Setup input goroutine.
	ctx.ExtSockIn[intf.Id] = rctx.NewSock(ringbuf.New(64, nil, "extIn", mkRingLabels(labels)),
		c, rcmn.DirExternal, intf.Id, labels, r.posixInput, r.handleSock)
	ctx.ExtSockOut[intf.Id] = rctx.NewSock(ringbuf.New(64, nil, "extOut", mkRingLabels(labels)),
		c, rcmn.DirExternal, intf.Id, labels, nil, r.posixOutput)
	log.Debug("Done setting up new external socket.", "intf", intf)
	return nil
}

// Create a set of labels for ringbuf with `sock` renamed to `ringId`.
func mkRingLabels(labels prometheus.Labels) prometheus.Labels {
	ringLabels := prom.CopyLabels(labels)
	ringLabels["ringId"] = labels["sock"]
	delete(ringLabels, "sock")
	return ringLabels
}

// rollbackPosixAddExt undoes the changes made by setupPosixAddExt.
func rollbackPosixAddExt(r *Router, ctx *rctx.Ctx, intf *netconf.Interface,
	oldCtx *rctx.Ctx) rpkt.HookResult {

	log.Debug("Rolling back external socket", "intf", intf)
	if oldCtx == nil {
		stopSock(ctx.ExtSockIn[intf.Id])
		stopSock(ctx.ExtSockOut[intf.Id])
		return rpkt.HookFinish
	}
	oldIntf, ok := oldCtx.Conf.Net.IFs[intf.Id]
	// The socket has been reused from old context and should not be closed.
	if ok && !interfaceChanged(intf, oldIntf) {
		return rpkt.HookContinue
	}
	stopSock(ctx.ExtSockIn[intf.Id])
	stopSock(ctx.ExtSockOut[intf.Id])
	// In case the old socket was closed in order to allow bind of new socket, restore it.
	if ok && intf.IFAddr.Equal(oldIntf.IFAddr) {
		labels := mkSockFromRingLabels(oldCtx.ExtSockIn[oldIntf.Id].Labels)
		if err := addPosixIntf(r, oldCtx, oldIntf, labels); err != nil {
			log.Crit("Unable to restart closed socket in rollback", err, "intf", oldIntf)
			if assert.On {
				assert.Must(false, "Must not fail to open socket in rollback")
			}
		} else {
			log.Debug("Restarting previously closed external sockets", "old", oldIntf, "new", intf)
			oldCtx.ExtSockIn[intf.Id].Start()
			oldCtx.ExtSockOut[intf.Id].Start()
		}
	}
	return rpkt.HookFinish
}

// Create a set of labels from ringbuf labels with `ringId` renamed to `sock`.
func mkSockFromRingLabels(labels prometheus.Labels) prometheus.Labels {
	sockLabel := prom.CopyLabels(labels)
	sockLabel["sock"] = labels["ringId"]
	delete(sockLabel, "ringId")
	return sockLabel
}

// teardownPosixLocal stops the unused local sockets in the old context.
func teardownPosixLocal(r *Router, ctx *rctx.Ctx, oldCtx *rctx.Ctx) rpkt.HookResult {
	if oldCtx != nil && ctx.LocSockIn != oldCtx.LocSockIn {
		if oldCtx.LocSockIn != nil {
			log.Debug("Tearing down unused local socket", "conn", ctx.LocSockIn.Conn.LocalAddr())
		}
		stopSock(oldCtx.LocSockIn)
		stopSock(oldCtx.LocSockOut)
	}
	return rpkt.HookFinish
}

// teardownPosixExt stops the unused external sockets in the old context.
func teardownPosixExt(r *Router, ctx *rctx.Ctx, oldCtx *rctx.Ctx) rpkt.HookResult {
	if oldCtx != nil {
		for ifid, oldSock := range oldCtx.ExtSockIn {
			if newSock, ok := ctx.ExtSockIn[ifid]; !ok || newSock != oldSock {
				stopSock(oldSock)
				stopSock(oldCtx.ExtSockOut[ifid])
			}
		}
	}
	return rpkt.HookFinish
}

// stopSock stops the socket or noop if it does not exist.
func stopSock(s *rctx.Sock) {
	if s != nil {
		s.Stop()
	}
}

// setupVerifyNoAddrTakeover ensures that an address is not take over by one interfaces
// from another. In the current setup, this requires a two step process.
func setupVerifyNoAddrTakeover(_ *Router, ctx, oldCtx *rctx.Ctx) (rpkt.HookResult, error) {
	if oldCtx == nil {
		return rpkt.HookFinish, nil
	}
	for ifid, intf := range ctx.Conf.Net.IFs {
		for oldIfid, oldIntf := range oldCtx.Conf.Net.IFs {
			if intf.IFAddr.Equal(oldIntf.IFAddr) && ifid != oldIfid {
				return rpkt.HookError, common.NewBasicError("Address must not switch intf", nil,
					"intf", intf, "oldIntf", oldIntf)
			}
			if ctx.Conf.Net.LocAddr.Equal(oldIntf.IFAddr) {
				return rpkt.HookError, common.NewBasicError("Address must not switch to local", nil,
					"oldIntf", intf, "locAddr", oldCtx.Conf.Net.LocAddr)
			}
		}
		if intf.IFAddr.Equal(oldCtx.Conf.Net.LocAddr) {
			return rpkt.HookError, common.NewBasicError("Address must not switch from local", nil,
				"intf", intf, "oldLocAddr", oldCtx.Conf.Net.LocAddr)
		}
	}
	return rpkt.HookFinish, nil
}
