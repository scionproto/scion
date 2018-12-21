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

var testInitOnce sync.Once

// setupTest sets up a test router.
func setupTestRouter(t *testing.T) (*Router, *rctx.Ctx) {
	// Init metrics and set hooks.
	testInitOnce.Do(func() {
		metrics.Init("br1-ff00_0_111-1")
		addPosixHooks()
	})
	// Set newConn to return dummy connections.
	newConn = func(_, _ *overlay.OverlayAddr, _ prometheus.Labels) (conn.Conn, error) {
		return &dummyConn{}, nil
	}
	r := &Router{}
	oldCtx := rctx.New(loadConfig(t))
	xtest.FailOnErr(t, r.setupNet(oldCtx, nil))
	startSocks(oldCtx)
	return r, oldCtx
}

func TestSetupNet(t *testing.T) {
	defer func() {
		newConn = conn.New
	}()
	Convey("Setting up a new context should only affect the appropriate parts", t, func() {
		r, oldCtx := setupTestRouter(t)
		Convey("Setting up the same config should be a noop", func() {
			copyCtx := copyContext(oldCtx)
			ctx := rctx.New(loadConfig(t))
			err := r.setupNet(ctx, copyCtx)
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

func TestRollbackNet(t *testing.T) {
	defer func() {
		newConn = conn.New
	}()
	Convey("Rolling back should only affect the appropriate parts", t, func() {
		r, oldCtx := setupTestRouter(t)
		Convey("Rolling back the same config should be a noop", func() {
			copyCtx := copyContext(oldCtx)
			ctx := rctx.New(loadConfig(t))
			err := r.setupNet(ctx, copyCtx)
			SoMsg("err", err, ShouldBeNil)
			r.rollbackNet(ctx, copyCtx)
			checkLocSocketsUnchanged(oldCtx, copyCtx)
			checkExtSocketsUnchanged(oldCtx, copyCtx)
		})
		Convey("Rolling back a config with changed local address should keep extSocks", func() {
			copyCtx := copyContext(oldCtx)
			ctx := rctx.New(loadConfig(t))
			ctx.Conf.Net.LocAddr.PublicOverlay(ctx.Conf.Net.LocAddr.Overlay).L3().IP()[0] = 255
			err := r.setupNet(ctx, copyCtx)
			SoMsg("err", err, ShouldBeNil)
			r.rollbackNet(ctx, copyCtx)
			checkLocSocketsUnchanged(oldCtx, copyCtx)
			checkExtSocketsUnchanged(oldCtx, copyCtx)
			checkLocSocketsRunning(oldCtx, true)
			checkLocSocketsRunning(ctx, false)
		})
		Convey("Rolling back a config with changed interface", func() {
			copyCtx := copyContext(oldCtx)
			ctx := rctx.New(loadConfig(t))
			Convey("Changing local address does not affect old socket", func() {
				ctx.Conf.Net.IFs[12].IFAddr.PublicOverlay(overlay.IPv4).L3().IP()[0] = 255
				err := r.setupNet(ctx, copyCtx)
				SoMsg("err", err, ShouldBeNil)
				r.rollbackNet(ctx, copyCtx)
				checkLocSocketsUnchanged(oldCtx, copyCtx)
				checkExtSocketsUnchanged(oldCtx, copyCtx)
				checkLocSocketsRunning(oldCtx, true)
				checkExtSocksRunning(oldCtx, true)

				SoMsg("New Ifid 12 In running", ctx.ExtSockIn[12].Running(), ShouldBeFalse)
				SoMsg("New ifid 12 Out running", ctx.ExtSockOut[12].Running(), ShouldBeFalse)
			})
			Convey("Changing remote address closes old socket", func() {
				ctx.Conf.Net.IFs[12].RemoteAddr.L3().IP()[0] = 255
				err := r.setupNet(ctx, copyCtx)
				SoMsg("err", err, ShouldBeNil)
				r.rollbackNet(ctx, copyCtx)
				checkLocSocketsUnchanged(oldCtx, copyCtx)
				checkLocSocketsRunning(oldCtx, true)

				SoMsg("IFID 11 In running", copyCtx.ExtSockIn[11].Running(), ShouldBeTrue)
				SoMsg("IFID 11 Out running", copyCtx.ExtSockOut[11].Running(), ShouldBeTrue)
				SoMsg("New IFID 12 In running", ctx.ExtSockIn[12].Running(), ShouldBeFalse)
				SoMsg("New IFID 12 Out running", ctx.ExtSockOut[12].Running(), ShouldBeFalse)
				SoMsg("Old IFID 12 In running", copyCtx.ExtSockIn[12].Running(), ShouldBeTrue)
				SoMsg("Old IFID 12 Out running", copyCtx.ExtSockOut[12].Running(), ShouldBeTrue)
				SoMsg("Orig IFID 12 In running", oldCtx.ExtSockIn[12].Running(), ShouldBeFalse)
				SoMsg("Orig IFID 12 Out running", oldCtx.ExtSockOut[12].Running(), ShouldBeFalse)
			})
		})
	})
}

func TestTeardownNet(t *testing.T) {
	defer func() {
		newConn = conn.New
	}()
	Convey("Tearing down should only affect the appropriate parts", t, func() {
		r, oldCtx := setupTestRouter(t)
		Convey("Tearing down the same config should be a noop", func() {
			copyCtx := copyContext(oldCtx)
			ctx := rctx.New(loadConfig(t))
			err := r.setupNet(ctx, copyCtx)
			SoMsg("err", err, ShouldBeNil)
			startSocks(ctx)
			cNewCtx := copyContext(ctx)
			r.teardownOldNet(ctx, copyCtx)
			checkLocSocketsUnchanged(ctx, cNewCtx)
			checkExtSocketsUnchanged(ctx, cNewCtx)
			checkExtSocksRunning(ctx, true)
			checkLocSocketsRunning(ctx, true)
		})
		Convey("Tearing down a config with changed local address should close old sock", func() {
			copyCtx := copyContext(oldCtx)
			ctx := rctx.New(loadConfig(t))
			ctx.Conf.Net.LocAddr.PublicOverlay(ctx.Conf.Net.LocAddr.Overlay).L3().IP()[0] = 255
			err := r.setupNet(ctx, copyCtx)
			SoMsg("err", err, ShouldBeNil)
			startSocks(ctx)
			cNewCtx := copyContext(ctx)
			r.teardownOldNet(ctx, copyCtx)
			checkLocSocketsUnchanged(ctx, cNewCtx)
			checkExtSocketsUnchanged(ctx, cNewCtx)
			checkExtSocksRunning(ctx, true)
			checkLocSocketsRunning(ctx, true)

			SoMsg("Old LocSock In running", copyCtx.LocSockIn.Running(), ShouldBeFalse)
			SoMsg("Old LocSock Out running", copyCtx.LocSockOut.Running(), ShouldBeFalse)

		})
		Convey("Tearing down a config with changed interface", func() {
			copyCtx := copyContext(oldCtx)
			ctx := rctx.New(loadConfig(t))
			Convey("Old socket closed", func() {
				ctx.Conf.Net.IFs[12].IFAddr.PublicOverlay(overlay.IPv4).L3().IP()[0] = 255
				err := r.setupNet(ctx, copyCtx)
				SoMsg("err", err, ShouldBeNil)
				startSocks(ctx)
				cNewCtx := copyContext(ctx)
				r.teardownOldNet(ctx, copyCtx)
				checkLocSocketsUnchanged(ctx, cNewCtx)
				checkExtSocketsUnchanged(ctx, cNewCtx)
				checkExtSocksRunning(ctx, true)
				checkLocSocketsRunning(ctx, true)

				SoMsg("Old Ifid 12 In running", copyCtx.ExtSockIn[12].Running(), ShouldBeFalse)
				SoMsg("Old ifid 12 Out running", copyCtx.ExtSockOut[12].Running(), ShouldBeFalse)
			})
			Convey("Old socket closed", func() {
				ctx.Conf.Net.IFs[12].RemoteAddr.L3().IP()[0] = 255
				err := r.setupNet(ctx, copyCtx)
				SoMsg("err", err, ShouldBeNil)
				startSocks(ctx)
				cNewCtx := copyContext(ctx)
				r.teardownOldNet(ctx, copyCtx)
				checkLocSocketsUnchanged(ctx, cNewCtx)
				checkExtSocketsUnchanged(ctx, cNewCtx)
				checkExtSocksRunning(ctx, true)
				checkLocSocketsRunning(ctx, true)

				SoMsg("Old IFID 12 In running", copyCtx.ExtSockIn[12].Running(), ShouldBeFalse)
				SoMsg("Old IFID 12 Out running", copyCtx.ExtSockOut[12].Running(), ShouldBeFalse)
				SoMsg("Orig IFID 12 In running", oldCtx.ExtSockIn[12].Running(), ShouldBeFalse)
				SoMsg("Orig IFID 12 Out running", oldCtx.ExtSockOut[12].Running(), ShouldBeFalse)
			})
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

func checkExtSocksRunning(ctx *rctx.Ctx, running bool) {
	for ifid, sock := range ctx.ExtSockIn {
		SoMsg(fmt.Sprintf("IFID %d In", ifid), sock.Running(), ShouldEqual, running)
	}
	for ifid, sock := range ctx.ExtSockOut {
		SoMsg(fmt.Sprintf("IFID %d Out", ifid), sock.Running(), ShouldEqual, running)
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

type dummyConn struct{}

func (d *dummyConn) Read(common.RawBytes) (int, *conn.ReadMeta, error) { return 0, nil, nil }

func (d *dummyConn) ReadBatch([]ipv4.Message, []conn.ReadMeta) (int, error) { return 0, nil }

func (d *dummyConn) Write(common.RawBytes) (int, error) { return 0, nil }

func (d *dummyConn) WriteTo(common.RawBytes, *overlay.OverlayAddr) (int, error) { return 0, nil }

func (d *dummyConn) WriteBatch([]ipv4.Message) (int, error) { return 0, nil }

func (d *dummyConn) LocalAddr() *overlay.OverlayAddr { return nil }

func (d *dummyConn) RemoteAddr() *overlay.OverlayAddr { return nil }

func (d *dummyConn) SetReadDeadline(time.Time) error { return nil }

func (d *dummyConn) Close() error { return nil }
