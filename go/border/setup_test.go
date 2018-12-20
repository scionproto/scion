// Copyright 2018 Anapaya Systems
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
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/net/ipv4"

	"github.com/scionproto/scion/go/border/brconf"
	"github.com/scionproto/scion/go/border/metrics"
	"github.com/scionproto/scion/go/border/netconf"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/overlay/conn"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
)

var testInitMetricsOnce sync.Once

func testInitMetrics() {
	testInitMetricsOnce.Do(func() {

		metrics.Init("br1-ff00_0_111-1")
	})
}

func TestSetupNet(t *testing.T) {
	testInitMetrics()
	defer func() {
		newConn = conn.New
	}()
	Convey("Given an initial context", t, func() {
		c := &closedConns{
			m: make(map[*dummyConn]struct{}),
		}
		setNewDummyConn(c)
		// Setup a dummy router with the initial config
		r := &Router{
			posixOutput: func(s *rctx.Sock, _, stopped chan struct{}) {
				for {
					c.mu.Lock()
					_, ok := c.m[s.Conn.(*dummyConn)]
					c.mu.Unlock()
					if ok {
						return
					}
					time.Sleep(time.Millisecond)
				}
			},
		}
		addPosixHooks()
		oldCtx := rctx.New(loadConfig(t))
		err := r.setupNet(oldCtx, nil)
		SoMsg("err", err, ShouldBeNil)
		startSocks(oldCtx)
		Convey("Setting up the same config should be a noop", func() {
			cOldCtx := copyContext(oldCtx)
			ctx := rctx.New(loadConfig(t))
			err := r.setupNet(ctx, cOldCtx)
			SoMsg("err", err, ShouldBeNil)
			checkLocSocketsUnchanged(ctx, oldCtx)
			checkExtSocketsUnchanged(ctx, oldCtx)
		})
		Convey("Setting up a config with changed local address should keep extSocks", func() {
			copyCtx := copyContext(oldCtx)
			ctx := rctx.New(loadConfig(t))
			ctx.Conf.Net.LocAddr.PublicOverlay(ctx.Conf.Net.LocAddr.Overlay).L3().IP()[0] = 255
			err := r.setupNet(ctx, copyCtx)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("LocSockIn changed", ctx.LocSockIn, ShouldNotEqual, oldCtx.LocSockIn)
			SoMsg("LocSockOut changed", ctx.LocSockOut, ShouldNotEqual, oldCtx.LocSockOut)
			checkExtSocketsUnchanged(ctx, oldCtx)
		})
		Convey("Setting up a config with changed interface should keep unaffected sockets", func() {
			copyCtx := copyContext(oldCtx)
			ctx := rctx.New(loadConfig(t))
			Convey("Changing local address does not affect old socket", func() {
				ctx.Conf.Net.IFs[12].IFAddr.PublicOverlay(overlay.IPv4).L3().IP()[0] = 255
				err := r.setupNet(ctx, copyCtx)
				SoMsg("err", err, ShouldBeNil)
				checkLocSocketsUnchanged(ctx, copyCtx)
				SoMsg("IFID 11", ctx.ExtSockIn[11], ShouldEqual, oldCtx.ExtSockIn[11])
				SoMsg("IFID 11", ctx.ExtSockOut[11], ShouldEqual, oldCtx.ExtSockOut[11])
				SoMsg("IFID 12", ctx.ExtSockIn[12], ShouldNotEqual, oldCtx.ExtSockIn[12])
				SoMsg("IFID 12", ctx.ExtSockOut[12], ShouldNotEqual, oldCtx.ExtSockOut[12])
				SoMsg("Old 12 In running", oldCtx.ExtSockIn[12].Running(), ShouldBeTrue)
				SoMsg("Old 12 Out running", oldCtx.ExtSockOut[12].Running(), ShouldBeTrue)
			})
			Convey("Changing remote address closes old socket", func() {
				ctx.Conf.Net.IFs[12].RemoteAddr.L3().IP()[0] = 255
				err := r.setupNet(ctx, copyCtx)
				SoMsg("err", err, ShouldBeNil)
				checkLocSocketsUnchanged(ctx, copyCtx)
				SoMsg("IFID 11", ctx.ExtSockIn[11], ShouldEqual, oldCtx.ExtSockIn[11])
				SoMsg("IFID 11", ctx.ExtSockOut[11], ShouldEqual, oldCtx.ExtSockOut[11])
				SoMsg("IFID 12", ctx.ExtSockIn[12], ShouldNotEqual, oldCtx.ExtSockIn[12])
				SoMsg("IFID 12", ctx.ExtSockOut[12], ShouldNotEqual, oldCtx.ExtSockOut[12])
				SoMsg("Old 12 In running", oldCtx.ExtSockIn[12].Running(), ShouldBeFalse)
				SoMsg("Old 12 Out running", oldCtx.ExtSockOut[12].Running(), ShouldBeFalse)
			})
		})
	})
}

func checkLocSocketsUnchanged(ctx, oldCtx *rctx.Ctx) {
	SoMsg("LocSockIn unchanged", ctx.LocSockIn, ShouldEqual, oldCtx.LocSockIn)
	SoMsg("LocSockOut unchanged", ctx.LocSockOut, ShouldEqual, oldCtx.LocSockOut)
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

func loadConfig(t *testing.T) *brconf.Conf {
	topo := loadTopo(t)
	topoBr, ok := topo.BR["br1-ff00_0_111-1"]
	if !ok {
		t.Fatal("BR ID not found")
	}
	net, err := netconf.FromTopo(topoBr.IFIDs, topo.IFInfoMap)
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

type closedConns struct {
	mu sync.Mutex
	m  map[*dummyConn]struct{}
}

func setNewDummyConn(c *closedConns) {
	newConn = func(_, _ *overlay.OverlayAddr, _ prometheus.Labels) (conn.Conn, error) {
		return &dummyConn{closed: c}, nil
	}
}

type dummyConn struct {
	closed *closedConns
}

func (d *dummyConn) Close() error {
	d.closed.mu.Lock()
	defer d.closed.mu.Unlock()
	d.closed.m[d] = struct{}{}
	return nil
}

func (d *dummyConn) Read(common.RawBytes) (int, *conn.ReadMeta, error) { return 0, nil, nil }

func (d *dummyConn) ReadBatch([]ipv4.Message, []conn.ReadMeta) (int, error) { return 0, nil }

func (d *dummyConn) Write(common.RawBytes) (int, error) { return 0, nil }

func (d *dummyConn) WriteTo(common.RawBytes, *overlay.OverlayAddr) (int, error) { return 0, nil }

func (d *dummyConn) WriteBatch([]ipv4.Message) (int, error) { return 0, nil }

func (d *dummyConn) LocalAddr() *overlay.OverlayAddr { return nil }

func (d *dummyConn) RemoteAddr() *overlay.OverlayAddr { return nil }

func (d *dummyConn) SetReadDeadline(time.Time) error { return nil }
