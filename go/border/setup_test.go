// Copyright 2019 Anapaya Systems
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
	"fmt"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/border/brconf"
	"github.com/scionproto/scion/go/border/metrics"
	"github.com/scionproto/scion/go/border/netconf"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/border/rpkt"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
)

var testInitOnce sync.Once

func TestSetupNet(t *testing.T) {
	Convey("Setting up the same config should be a noop", t, func() {
		r, oldCtx := setupTestRouter(t)
		ctx := rctx.New(loadConfig(t))
		clean := updateTestRouter(r, ctx, oldCtx)
		defer clean()
		// Check that the sockets are reused if nothing changes.
		checkLocSocksUnchanged("New vs Old", ctx, oldCtx)
		checkExtSocksUnchanged("New vs Old", ctx, oldCtx)
		// Check that all sockets are still running
		checkLocSocksRunning("ctx", ctx, true)
		checkExtSocksRunning("ctx", ctx, true)
	})
	Convey("Setting up a config with changed local address should keep extSocks", t, func() {
		r, oldCtx := setupTestRouter(t)
		ctx := rctx.New(loadConfig(t))
		// Modify local socket address. A new socket should be opened when
		// setting up the context.
		ctx.Conf.Net.LocAddr.PublicOverlay(ctx.Conf.Net.LocAddr.Overlay).L3().IP()[3] = 255
		clean := updateTestRouter(r, ctx, oldCtx)
		defer clean()
		// Check that the local socket changed
		SoMsg("LocSockIn changed", ctx.LocSockIn, ShouldNotEqual, oldCtx.LocSockIn)
		SoMsg("LocSockOut changed", ctx.LocSockOut, ShouldNotEqual, oldCtx.LocSockOut)
		// Check that the external sockets are unchanged.
		checkExtSocksUnchanged("New vs Old", ctx, oldCtx)
		// Check that external sockets are still running.
		checkExtSocksRunning("ctx", ctx, true)
		// FIXME(roosd): Check state of the local socket when reload logic is improved.
	})
	// FIXME(roosd): Add more tests to test the correct behavior when reload logic is improved.
	// Due to the currently faulty reload logic, the additional tests would fail.
}

// checkLocSocksUnchanged compares that both contexts point to the same local socket.
func checkLocSocksUnchanged(key string, ctx, oldCtx *rctx.Ctx) {
	SoMsg(fmt.Sprintf("%s: LocSockIn unchanged", key), ctx.LocSockIn, ShouldEqual, oldCtx.LocSockIn)
	SoMsg(fmt.Sprintf("%s: LocSockOut unchanged", key),
		ctx.LocSockOut, ShouldEqual, oldCtx.LocSockOut)
}

// checkExtSocksUnchaged compares that both contexts point to the same external sockets.
func checkExtSocksUnchanged(key string, ctx, oldCtx *rctx.Ctx) {
	// Check that all sockets that are in oldCtx are in ctx.
	compareExtSocksEq(key, oldCtx.ExtSockIn, ctx.ExtSockIn, "oldCtxIn vs ctxIn")
	compareExtSocksEq(key, oldCtx.ExtSockOut, ctx.ExtSockOut, "oldCtxOut vs ctxOut")
	// Check that all sockets that are in ctx are in oldCtx
	compareExtSocksEq(key, ctx.ExtSockIn, oldCtx.ExtSockIn, "ctxIn vs oldCtxIn")
	compareExtSocksEq(key, ctx.ExtSockOut, oldCtx.ExtSockOut, "ctxOut vs oldCtxOut")
}

func compareExtSocksEq(key string, a, b map[common.IFIDType]*rctx.Sock, suffix string) {
	for ifid, sock := range a {
		SoMsg(fmt.Sprintf("%s: IFID %d %s", key, ifid, suffix), sock, ShouldEqual, b[ifid])
	}
}

func checkLocSocksRunning(key string, ctx *rctx.Ctx, running bool) {
	SoMsg(fmt.Sprintf("%s: LocSockIn running", key), ctx.LocSockIn.Running(), ShouldEqual, running)
	SoMsg(fmt.Sprintf("%s: LocSockOut running", key),
		ctx.LocSockOut.Running(), ShouldEqual, running)
}

func checkExtSocksRunning(key string, ctx *rctx.Ctx, running bool) {
	for ifid, sock := range ctx.ExtSockIn {
		SoMsg(fmt.Sprintf("%s: IFID %d In", key, ifid), sock.Running(), ShouldEqual, running)
	}
	for ifid, sock := range ctx.ExtSockOut {
		SoMsg(fmt.Sprintf("%s: IFID %d Out", key, ifid), sock.Running(), ShouldEqual, running)
	}
}

// setupTest sets up a test router. The test router is initially set up with the
// topology loaded from testdata.
func setupTestRouter(t *testing.T) (*Router, *rctx.Ctx) {
	// Init metrics.
	testInitOnce.Do(func() {
		metrics.Init("br1-ff00_0_111-1")
		// Reduce output displayed in goconvey.
		log.Root().SetHandler(log.DiscardHandler())
	})
	// The number of free packets has to be at least the number of posix
	// input routines times inputBufCnt. Otherwise they might get stuck
	// trying to prepare for reading from the connection.
	// See: https://github.com/scionproto/scion/issues/1981
	maxNumPosixInput := 4
	// Initialize router with the topology.
	r := &Router{
		freePkts: ringbuf.New(maxNumPosixInput*inputBufCnt, func() interface{} {
			return rpkt.NewRtrPkt()
		}, "free", prometheus.Labels{"ringId": "freePkts"}),
	}
	sockConf := brconf.SockConf{Default: PosixSock}
	// oldCtx contains the testdata topology.
	oldCtx := rctx.New(loadConfig(t))
	xtest.FailOnErr(t, r.setupNet(oldCtx, nil, sockConf))
	startSocks(oldCtx)
	return r, oldCtx
}

// updateTestRouter calls setupNet on the provided router with new and old context.
// The cleanup function shall be called to free the allocated sockets.
func updateTestRouter(r *Router, newCtx, oldCtx *rctx.Ctx) func() {
	// Call setupNet with provided new context. Copy context to catch
	// map alterations.
	copyCtx := copyContext(oldCtx)
	err := r.setupNet(newCtx, copyCtx, brconf.SockConf{Default: PosixSock})
	SoMsg("err", err, ShouldBeNil)
	// Close all sockets to allow binding in subsequent tests.
	cleanUp := func() {
		closeAllSocks(newCtx)
		closeAllSocks(oldCtx)
		closeAllSocks(copyCtx)
	}
	return cleanUp
}

func copyContext(ctx *rctx.Ctx) *rctx.Ctx {
	c := &rctx.Ctx{}
	*c = *ctx
	c.ExtSockIn = make(map[common.IFIDType]*rctx.Sock)
	c.ExtSockOut = make(map[common.IFIDType]*rctx.Sock)
	for ifid, sock := range ctx.ExtSockIn {
		c.ExtSockIn[ifid] = sock
	}
	for ifid, sock := range ctx.ExtSockOut {
		c.ExtSockOut[ifid] = sock
	}
	return c
}

func closeAllSocks(ctx *rctx.Ctx) {
	if ctx != nil {
		ctx.LocSockIn.Stop()
		ctx.LocSockOut.Stop()
		for ifid := range ctx.ExtSockIn {
			ctx.ExtSockIn[ifid].Stop()
			ctx.ExtSockOut[ifid].Stop()
		}
	}
}

func loadConfig(t *testing.T) *brconf.Conf {
	topo := loadTopo(t)
	topoBr, ok := topo.BR["br1-ff00_0_111-1"]
	if !ok {
		t.Fatal("BR ID not found")
	}
	net, err := netconf.FromTopo(&topoBr, topo.IFInfoMap)
	xtest.FailOnErr(t, err)
	return &brconf.Conf{
		Topo: topo,
		IA:   topo.ISD_AS,
		BR:   &topoBr,
		Net:  net,
	}
}

func loadTopo(t *testing.T) *topology.Topo {
	topo, err := topology.LoadFromFile("testdata/topology.json")
	xtest.FailOnErr(t, err)
	return topo
}
