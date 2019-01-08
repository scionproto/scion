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
		ctx := rctx.New(loadConfig(t))
		oldCtx, cleanUp := setupTestRouter(t, ctx)
		defer cleanUp()
		checkLocSocksUnchanged("", ctx, oldCtx)
		checkExtSocksUnchanged("", ctx, oldCtx)
	})
	Convey("Setting up a config with changed local address should keep extSocks", t, func() {
		ctx := rctx.New(loadConfig(t))
		ctx.Conf.Net.LocAddr.PublicOverlay(ctx.Conf.Net.LocAddr.Overlay).L3().IP()[3] = 255
		oldCtx, cleanUp := setupTestRouter(t, ctx)
		defer cleanUp()
		SoMsg("LocSockIn changed", ctx.LocSockIn, ShouldNotEqual, oldCtx.LocSockIn)
		SoMsg("LocSockOut changed", ctx.LocSockOut, ShouldNotEqual, oldCtx.LocSockOut)
		checkExtSocksUnchanged("New vs Old", ctx, oldCtx)
	})
}

func checkLocSocksUnchanged(key string, ctx, oldCtx *rctx.Ctx) {
	SoMsg(fmt.Sprintf("%s: LocSockIn unchanged", key), ctx.LocSockIn, ShouldEqual, oldCtx.LocSockIn)
	SoMsg(fmt.Sprintf("%s: LocSockOut unchanged", key),
		ctx.LocSockOut, ShouldEqual, oldCtx.LocSockOut)
}

func checkExtSocksUnchanged(key string, ctx, oldCtx *rctx.Ctx) {
	compareExtSocksEq(key, oldCtx.ExtSockIn, ctx.ExtSockIn, "aIn vs bIn")
	compareExtSocksEq(key, oldCtx.ExtSockOut, ctx.ExtSockOut, "aOut vs bOut")
	compareExtSocksEq(key, ctx.ExtSockIn, oldCtx.ExtSockIn, "bIn vs aIn")
	compareExtSocksEq(key, ctx.ExtSockOut, oldCtx.ExtSockOut, "bOut vs aOut")
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

// setupTest sets up a test router.
func setupTestRouter(t *testing.T, newCtx *rctx.Ctx) (*rctx.Ctx, func()) {
	// Init metrics.
	testInitOnce.Do(func() {
		metrics.Init("br1-ff00_0_111-1")
		// Reduce output displayed in goconvey.
		log.Root().SetHandler(log.DiscardHandler())
	})
	// Initialize router with the topology.
	r := &Router{
		freePkts: ringbuf.New(1024, func() interface{} {
			return rpkt.NewRtrPkt()
		}, "free", prometheus.Labels{"ringId": "freePkts"}),
	}
	sockConf := brconf.SockConf{Default: PosixSock}
	oldCtx := rctx.New(loadConfig(t))
	xtest.FailOnErr(t, r.setupNet(oldCtx, nil, sockConf))
	startSocks(oldCtx)
	// Call setupNet with provided new context. Copy context to catch
	// map alterations.
	copyCtx := copyContext(oldCtx)
	err := r.setupNet(newCtx, copyCtx, sockConf)
	SoMsg("err", err, ShouldBeNil)
	// Close all sockets to allow binding in subsequent tests.
	cleanUp := func() {
		closeAllSocks(newCtx)
		closeAllSocks(oldCtx)
		closeAllSocks(copyCtx)
	}
	return oldCtx, cleanUp
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
		stopSock(ctx.LocSockIn)
		stopSock(ctx.LocSockOut)
		for ifid := range ctx.ExtSockIn {
			stopSock(ctx.ExtSockIn[ifid])
			stopSock(ctx.ExtSockOut[ifid])
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
