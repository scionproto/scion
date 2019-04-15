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

package keepalive

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/beacon_srv/internal/ifstate"
	"github.com/scionproto/scion/go/beacon_srv/internal/keepalive/mock_keepalive"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/ifid"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	localIF  = common.IFIDType(10)
	originIF = common.IFIDType(11)
	localIA  = xtest.MustParseIA("1-ff00:0:110")
	originIA = xtest.MustParseIA("1-ff00:0:111")
)

// Disable logging in all tests
func TestMain(m *testing.M) {
	log.Root().SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}

func TestNewHandler(t *testing.T) {
	Convey("NewHandler creates a correct handler", t, func() {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()

		Convey("Non-active interface should cause tasks to execute", func() {
			// The wait group ensures all go routines are finished before
			// the test finishes.
			wg := &sync.WaitGroup{}
			wg.Add(4)
			// Make sure the mock is executed exactly once and updates the waitgroup.
			set := func(call *gomock.Call) *gomock.Call {
				return call.Times(1).Do(func(_ ...interface{}) { wg.Done() })
			}

			pusher := mock_keepalive.NewMockIfStatePusher(mctrl)
			beaconer := mock_keepalive.NewMockBeaconer(mctrl)
			dropper := mock_keepalive.NewMockRevDropper(mctrl)
			set(pusher.EXPECT().Push(gomock.Any()))
			set(beaconer.EXPECT().Beacon(gomock.Any(), localIF))
			set(dropper.EXPECT().DeleteRevocation(gomock.Any(), localIA, localIF)).Return(0, nil)
			set(dropper.EXPECT().DeleteRevocation(gomock.Any(), originIA, originIF)).Return(0, nil)

			handler := NewHandler(localIA, testInterfaces(), StateChangeTasks{
				IfStatePusher: pusher,
				Beaconer:      beaconer,
				RevDropper:    dropper,
			})
			req := infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: originIF}, nil,
				&snet.Addr{IA: originIA, Path: testPath(localIF)}, 0)
			res := handler.Handle(req)
			waitTimeout(wg)
			SoMsg("res", res, ShouldEqual, infra.MetricsResultOk)
		})
		Convey("Active interface should cause no tasks to execute", func() {
			intfs := testInterfaces()
			intfs.Get(localIF).Activate(42)
			handler := NewHandler(localIA, intfs, zeroCallTasks(mctrl))
			req := infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: originIF}, nil,
				&snet.Addr{IA: originIA, Path: testPath(localIF)}, 0)
			res := handler.Handle(req)
			SoMsg("res", res, ShouldEqual, infra.MetricsResultOk)
		})
		Convey("Invalid requests cause an error", func() {
			handler := NewHandler(localIA, testInterfaces(), zeroCallTasks(mctrl))
			Convey("Wrong payload type", func() {
				req := infra.NewRequest(context.Background(), &ctrl.Pld{}, nil,
					&snet.Addr{IA: originIA, Path: testPath(localIF)}, 0)
				res := handler.Handle(req)
				SoMsg("res", res, ShouldEqual, infra.MetricsErrInternal)
			})
			Convey("Invalid address type", func() {
				req := infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: originIF}, nil,
					&net.UnixAddr{}, 0)
				res := handler.Handle(req)
				SoMsg("res", res, ShouldEqual, infra.MetricsErrInvalid)
			})
			Convey("Invalid path", func() {
				req := infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: originIF}, nil,
					&snet.Addr{IA: originIA, Path: &spath.Path{}}, 0)
				res := handler.Handle(req)
				SoMsg("res", res, ShouldEqual, infra.MetricsErrInvalid)
			})
			Convey("Invalid ConsIngress ifid", func() {
				req := infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: originIF}, nil,
					&snet.Addr{IA: originIA, Path: testPath(originIF)}, 0)
				res := handler.Handle(req)
				SoMsg("res", res, ShouldEqual, infra.MetricsErrInvalid)
			})
			Convey("Invalid IA", func() {
				req := infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: originIF}, nil,
					&snet.Addr{IA: localIA, Path: testPath(localIF)}, 0)
				res := handler.Handle(req)
				SoMsg("res", res, ShouldEqual, infra.MetricsErrInvalid)
			})
		})
	})
}

func testInterfaces() *ifstate.Interfaces {
	infoMap := topology.IfInfoMap{localIF: topology.IFInfo{ISD_AS: originIA}}
	return ifstate.NewInterfaces(infoMap, ifstate.Config{})
}

func zeroCallTasks(mctrl *gomock.Controller) StateChangeTasks {
	return StateChangeTasks{
		IfStatePusher: mock_keepalive.NewMockIfStatePusher(mctrl),
		Beaconer:      mock_keepalive.NewMockBeaconer(mctrl),
		RevDropper:    mock_keepalive.NewMockRevDropper(mctrl),
	}
}

func testPath(ifid common.IFIDType) *spath.Path {
	path := &spath.Path{
		Raw:    make(common.RawBytes, spath.InfoFieldLength+spath.HopFieldLength),
		HopOff: spath.InfoFieldLength,
	}
	(&spath.HopField{ConsIngress: ifid}).Write(path.Raw[spath.InfoFieldLength:])
	return path
}

func waitTimeout(wg *sync.WaitGroup) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-time.After(5 * time.Second):
		SoMsg("Timed out", 1, ShouldBeFalse)
	case <-done:
	}
}
