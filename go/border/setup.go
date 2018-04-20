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

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/syndtr/gocapability/capability"

	"github.com/scionproto/scion/go/border/conf"
	"github.com/scionproto/scion/go/border/ifstate"
	"github.com/scionproto/scion/go/border/metrics"
	"github.com/scionproto/scion/go/border/netconf"
	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay/conn"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/topology"
)

type setupNetHook func(r *Router, ctx *rctx.Ctx,
	oldCtx *rctx.Ctx) (rpkt.HookResult, error)
type setupAddLocalHook func(r *Router, ctx *rctx.Ctx, idx int, ta *topology.TopoAddr,
	labels prometheus.Labels, oldCtx *rctx.Ctx) (rpkt.HookResult, error)
type setupAddExtHook func(r *Router, ctx *rctx.Ctx, intf *netconf.Interface,
	labels prometheus.Labels, oldCtx *rctx.Ctx) (rpkt.HookResult, error)

// Setup hooks enables the network stack to be modular. Any network stack that
// wants to be included defines its own init function which adds hooks to these
// hook slices. See setup-hsr.go for an example.
var setupNetStartHooks []setupNetHook
var setupAddLocalHooks []setupAddLocalHook
var setupAddExtHooks []setupAddExtHook
var setupNetFinishHooks []setupNetHook

// setup creates the router's channels and map, sets up the rpkt package, and
// sets up a new router context. This function can only be called once during startup.
func (r *Router) setup() error {
	r.freePkts = ringbuf.New(1024, func() interface{} {
		return rpkt.NewRtrPkt()
	}, "free", prometheus.Labels{"ringId": "freePkts"})
	r.revInfoQ = make(chan rpkt.RevTokenCallbackArgs, 16)
	r.ifIDQ = make(chan rpkt.IFIDCallbackArgs, 16)
	r.pktErrorQ = make(chan pktErrorArgs, 16)

	// Configure the rpkt package with the callbacks it needs.
	rpkt.Init(r.RevTokenCallback, r.IFIDCallback)

	// Add default posix setup hooks. If there are other hooks, they should install
	// themselves via init(), so they appear before the posix ones.
	setupAddLocalHooks = append(setupAddLocalHooks, setupPosixAddLocal)
	setupAddExtHooks = append(setupAddExtHooks, setupPosixAddExt)

	// Load config.
	var err error
	var config *conf.Conf
	if config, err = r.loadNewConfig(); err != nil {
		return err
	}
	// Setup new context.
	if err = r.setupNewContext(config); err != nil {
		return err
	}
	// Clear capabilities after setting up the network. Capabilities are currently
	// only needed by the HSR for which the router never reconfigures the network.
	if err = r.clearCapabilities(); err != nil {
		return err
	}
	// Export prometheus metrics.
	if err = metrics.Start(); err != nil {
		return err
	}
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

// loadNewConfig loads a new conf.Conf object from the configuration file.
func (r *Router) loadNewConfig() (*conf.Conf, error) {
	var config *conf.Conf
	var err error
	if config, err = conf.Load(r.Id, r.confDir); err != nil {
		return nil, err
	}
	log.Debug("Topology and AS config loaded", "IA", config.IA, "IfIDs", config.BR, "dir", r.confDir)
	return config, nil
}

// setupNewContext sets up a new router context.
func (r *Router) setupNewContext(config *conf.Conf) error {
	oldCtx := rctx.Get()
	ctx := rctx.New(config, len(config.Net.LocAddr))
	if err := r.setupNet(ctx, oldCtx); err != nil {
		return err
	}
	rctx.Set(ctx)
	// Start local input functions.
	for _, s := range ctx.LocSockIn {
		s.Start()
	}
	// Start local output functions.
	for _, s := range ctx.LocSockOut {
		s.Start()
	}
	// Start external input functions.
	for _, s := range ctx.ExtSockIn {
		s.Start()
	}
	// Start external output functions.
	for _, s := range ctx.ExtSockOut {
		s.Start()
	}
	// Clean-up interface state infos that are not present anymore.
	if oldCtx != nil {
		for ifID := range oldCtx.Conf.Topo.IFInfoMap {
			if _, ok := ctx.Conf.Topo.IFInfoMap[ifID]; !ok {
				ifstate.DeleteState(ifID)
			}
		}
	}
	return nil
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
	for i, a := range ctx.Conf.Net.LocAddr {
		labels := prometheus.Labels{"sock": fmt.Sprintf("loc:%d", i)}
		for _, f := range setupAddLocalHooks {
			ret, err := f(r, ctx, i, a, labels, oldCtx)
			switch {
			case err != nil:
				return err
			case ret == rpkt.HookContinue:
				continue
			case ret == rpkt.HookFinish:
				break
			}
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
	// Stop input functions that are no longer needed.
	if oldCtx != nil {
		for i := len(ctx.LocSockIn); i < len(oldCtx.LocSockIn); i++ {
			oldCtx.LocSockIn[i].Stop()
		}
		for ifid, sock := range oldCtx.ExtSockIn {
			if _, ok := ctx.ExtSockIn[ifid]; !ok {
				sock.Stop()
			}
		}
	}
	return nil
}

// setupPosixAddLocal configures a local POSIX(/BSD) socket.
func setupPosixAddLocal(r *Router, ctx *rctx.Ctx, idx int, ta *topology.TopoAddr,
	labels prometheus.Labels, oldCtx *rctx.Ctx) (rpkt.HookResult, error) {
	// No old context. This happens during startup of the router.
	pai := ta.PublicAddrInfo(ctx.Conf.Topo.Overlay)
	bai := ta.BindAddrInfo(ctx.Conf.Topo.Overlay)
	if oldCtx == nil {
		if err := addPosixLocal(r, ctx, idx, bai, labels); err != nil {
			return rpkt.HookError, err
		}
		return rpkt.HookFinish, nil
	}
	// FIXME(kormat): cases not currently handled:
	// - a local addr moves idx
	// - a local addr has its bind address change
	if oldIdx, ok := oldCtx.Conf.Net.LocAddrMap[pai.Key()]; !ok {
		// New local address got added. Configure Posix I/O.
		if err := addPosixLocal(r, ctx, idx, bai, labels); err != nil {
			return rpkt.HookError, err
		}
	} else {
		log.Debug("No change detected for local socket.", "pubAddr", pai)
		// Nothing changed. Copy I/O functions from old context.
		ctx.LocSockIn[idx] = oldCtx.LocSockIn[oldIdx]
		ctx.LocSockOut[idx] = oldCtx.LocSockOut[oldIdx]
	}
	return rpkt.HookFinish, nil
}

func addPosixLocal(r *Router, ctx *rctx.Ctx, idx int, ba *topology.AddrInfo,
	labels prometheus.Labels) error {
	// FIXME(kormat): this does not support dual-stack local addresses (e.g. ipv4+6).
	// Listen on the socket.
	over, err := conn.New(ba, nil, labels)
	if err != nil {
		return common.NewBasicError("Unable to listen on local socket", err)
	}
	// Find interfaces that use this local address.
	var ifids []common.IFIDType
	for _, intf := range ctx.Conf.Net.IFs {
		if intf.LocAddrIdx == idx {
			ifids = append(ifids, intf.Id)
		}
	}
	// Setup input goroutine.
	ctx.LocSockIn[idx] = rctx.NewSock(ringbuf.New(64, nil, "locIn", mkRingLabels(labels)),
		over, rcmn.DirLocal, ifids, idx, labels, r.posixInput, r.handleSock)
	ctx.LocSockOut[idx] = rctx.NewSock(ringbuf.New(64, nil, "locOut", mkRingLabels(labels)),
		over, rcmn.DirLocal, ifids, idx, labels, nil, r.posixOutput)
	log.Debug("Set up new local socket.", "conn", over.LocalAddr())
	return nil
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
	if oldIntf, ok := oldCtx.Conf.Net.IFs[intf.Id]; !ok {
		// New interface got added. Configure Posix I/O.
		if err := addPosixIntf(r, ctx, intf, labels); err != nil {
			return rpkt.HookError, err
		}
	} else if interfaceChanged(intf, oldIntf) {
		log.Debug("Existing interface changed.", "old", oldIntf, "new", intf)
		// An existing interface has changed.
		// Stop old input goroutine.
		oldCtx.ExtSockIn[intf.Id].Stop()
		oldCtx.ExtSockOut[intf.Id].Stop()
		// Configure new Posix I/O.
		if err := addPosixIntf(r, ctx, intf, labels); err != nil {
			return rpkt.HookError, err
		}
	} else {
		log.Debug("No change detected for external socket.", "conn",
			intf.IFAddr.BindAddrInfo(ctx.Conf.Topo.Overlay))
		// Nothing changed. Copy I/O functions from old context.
		ctx.ExtSockIn[intf.Id] = oldCtx.ExtSockIn[intf.Id]
		ctx.ExtSockOut[intf.Id] = oldCtx.ExtSockOut[intf.Id]
	}
	return rpkt.HookFinish, nil
}

// interfaceChanged returns true if a new input goroutine is needed for the
// corresponding interface.
func interfaceChanged(newIntf *netconf.Interface, oldIntf *netconf.Interface) bool {
	return (newIntf.Id != oldIntf.Id ||
		!newIntf.IFAddr.Equal(oldIntf.IFAddr) ||
		newIntf.RemoteAddr.String() != oldIntf.RemoteAddr.String())
}

func addPosixIntf(r *Router, ctx *rctx.Ctx, intf *netconf.Interface,
	labels prometheus.Labels) error {
	// Connect to remote address.
	ba := intf.IFAddr.BindAddrInfo(intf.IFAddr.Overlay)
	c, err := conn.New(ba, intf.RemoteAddr, labels)
	if err != nil {
		return common.NewBasicError("Unable to listen on external socket", err)
	}
	ifids := []common.IFIDType{intf.Id}
	// Setup input goroutine.
	ctx.ExtSockIn[intf.Id] = rctx.NewSock(ringbuf.New(64, nil, "extIn", mkRingLabels(labels)),
		c, rcmn.DirExternal, ifids, -1, labels, r.posixInput, r.handleSock)
	ctx.ExtSockOut[intf.Id] = rctx.NewSock(ringbuf.New(64, nil, "extOut", mkRingLabels(labels)),
		c, rcmn.DirExternal, ifids, -1, labels, nil, r.posixOutput)
	log.Debug("Set up new external socket.", "intf", intf)
	return nil
}

// Create a set of labels for ringbuf with `sock` renamed to `ringId`.
func mkRingLabels(labels prometheus.Labels) prometheus.Labels {
	ringLabels := prom.CopyLabels(labels)
	ringLabels["ringId"] = labels["sock"]
	delete(ringLabels, "sock")
	return ringLabels
}
