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
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
)

var testInitOnce sync.Once

func TestSetupNet(t *testing.T) {
	Convey("Setting up a new context should only affect the appropriate parts", t, func() {
		Convey("Setting up the same config should be a noop", func() {
			ctx := rctx.New(loadConfig(t))
			oldCtx, cleanUp := setupTestRouter(t, ctx)
			defer cleanUp()
			checkLocSocketsUnchanged(ctx, oldCtx)
			checkExtSocketsUnchanged(ctx, oldCtx)
		})
		Convey("Setting up a config with changed local address should keep extSocks", func() {
			ctx := rctx.New(loadConfig(t))
			ctx.Conf.Net.LocAddr.PublicOverlay(ctx.Conf.Net.LocAddr.Overlay).L3().IP()[3] = 255
			oldCtx, cleanUp := setupTestRouter(t, ctx)
			defer cleanUp()
			SoMsg("LocSockIn changed", ctx.LocSockIn, ShouldNotEqual, oldCtx.LocSockIn)
			SoMsg("LocSockOut changed", ctx.LocSockOut, ShouldNotEqual, oldCtx.LocSockOut)
			checkExtSocketsUnchanged(ctx, oldCtx)
		})
	})
}

func checkLocSocketsUnchanged(ctx, oldCtx *rctx.Ctx) {
	SoMsg("LocSockIn unchanged", ctx.LocSockIn, ShouldEqual, oldCtx.LocSockIn)
	SoMsg("LocSockOut unchanged", ctx.LocSockOut, ShouldEqual, oldCtx.LocSockOut)
}

func checkLocSocketsRunning(ctx *rctx.Ctx, running bool) {
	SoMsg("LocSockIn running", ctx.LocSockIn.Running(), ShouldEqual, running)
	SoMsg("LocSockOut running", ctx.LocSockOut.Running(), ShouldEqual, running)
}

func checkExtSocketsUnchanged(ctx, oldCtx *rctx.Ctx) {
	compareExtSocksEq(oldCtx.ExtSockIn, ctx.ExtSockIn, "oldIn vs In")
	compareExtSocksEq(oldCtx.ExtSockOut, ctx.ExtSockOut, "oldOut vs Out")
	compareExtSocksEq(ctx.ExtSockIn, oldCtx.ExtSockIn, "In vs oldIn")
	compareExtSocksEq(ctx.ExtSockOut, oldCtx.ExtSockOut, "Out vs oldOut")
}

func compareExtSocksEq(a, b map[common.IFIDType]*rctx.Sock, suffix string) {
	for ifid, sock := range a {
		SoMsg(fmt.Sprintf("IFID %d %s", ifid, suffix), sock, ShouldEqual, b[ifid])
	}
}

// setupTest sets up a test router.
func setupTestRouter(t *testing.T, newCtx *rctx.Ctx) (*rctx.Ctx, func()) {
	// Init metrics.
	testInitOnce.Do(func() {
		metrics.Init("br1-ff00_0_111-1")
	})
	// Initialize router with the topology.
	r := &Router{
		freePkts: ringbuf.New(1024, func() interface{} {
			return rpkt.NewRtrPkt()
		}, "free", prometheus.Labels{"ringId": "freePkts"}),
	}
	oldCtx := rctx.New(loadConfig(t))
	xtest.FailOnErr(t, r.setupNet(oldCtx, nil, SocketConf{}))
	startSocks(oldCtx)
	// Call setupNet with provided new context. Copy context to catch
	// map alterations.
	copyCtx := copyContext(oldCtx)
	err := r.setupNet(newCtx, copyCtx, SocketConf{})
	SoMsg("err", err, ShouldBeNil)
	// Close all sockets to allow binding in subsequent tests.
	cleanUp := func() {
		closeAllSocks(newCtx)
		closeAllSocks(oldCtx)
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
