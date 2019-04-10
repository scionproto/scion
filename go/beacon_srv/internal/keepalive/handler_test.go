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
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	localIF  = common.IFIDType(10)
	remoteIF = common.IFIDType(11)
	localIA  = xtest.MustParseIA("1-ff00:0:110")
	remoteIA = xtest.MustParseIA("1-ff00:0:111")
)

func TestNewHandler(t *testing.T) {
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	Convey("NewHandler crates a correct handler", t, func() {
		Convey("Non-active interface should cause tasks to execute", func() {
			// Make sure all mocks are executed in the go routine exactly
			// once. The wait group is to ensure all are finished before
			// the test finishes.
			wg := &sync.WaitGroup{}
			wg.Add(4)
			set := func(call *gomock.Call) *gomock.Call {
				return call.MinTimes(1).MaxTimes(1).Do(func(_ ...interface{}) { wg.Done() })
			}

			pusher := mock_keepalive.NewMockIfStatePusher(mctrl)
			beaconer := mock_keepalive.NewMockBeaconer(mctrl)
			dropper := mock_keepalive.NewMockRevDropper(mctrl)
			set(pusher.EXPECT().Push(gomock.Any()))
			set(beaconer.EXPECT().Beacon(gomock.Any(), localIF))
			set(dropper.EXPECT().DeleteRevocation(gomock.Any(), localIA, localIF)).Return(0, nil)
			set(dropper.EXPECT().DeleteRevocation(gomock.Any(), remoteIA, remoteIF)).Return(0, nil)

			handler := NewHandler(localIA, initInfos(), StateChangeTasks{
				IfStatePusher: pusher,
				Beaconer:      beaconer,
				RevDropper:    dropper,
			})
			req := infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: remoteIF}, nil,
				&snet.Addr{IA: remoteIA, Path: testPath(localIF)}, 0)
			res := handler.Handle(req)
			waitTimeout(wg)
			SoMsg("res", res, ShouldEqual, infra.MetricsResultOk)
		})
		Convey("Active interface should cause no tasks to execute", func() {
			infos := initInfos()
			infos.Get(localIF).Activate(42)
			handler := NewHandler(localIA, infos, zeroCallTasks(mctrl))
			req := infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: remoteIF}, nil,
				&snet.Addr{IA: remoteIA, Path: testPath(localIF)}, 0)
			res := handler.Handle(req)
			SoMsg("res", res, ShouldEqual, infra.MetricsResultOk)
		})
		Convey("Invalid requests cause an error", func() {
			infos := initInfos()
			handler := NewHandler(localIA, infos, zeroCallTasks(mctrl))
			Convey("Wrong payload type", func() {
				req := infra.NewRequest(context.Background(), &ctrl.Pld{}, nil,
					&snet.Addr{IA: remoteIA, Path: testPath(localIF)}, 0)
				res := handler.Handle(req)
				SoMsg("res", res, ShouldEqual, infra.MetricsErrInternal)
			})
			Convey("Invalid address type", func() {
				req := infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: remoteIF}, nil,
					&net.UnixAddr{}, 0)
				res := handler.Handle(req)
				SoMsg("res", res, ShouldEqual, infra.MetricsErrInternal)
			})
			Convey("Invalid path", func() {
				req := infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: remoteIF}, nil,
					&snet.Addr{IA: remoteIA, Path: &spath.Path{}}, 0)
				res := handler.Handle(req)
				SoMsg("res", res, ShouldEqual, infra.MetricsErrInvalid)
			})
			Convey("Invalid ConsIngress ifid", func() {
				req := infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: remoteIF}, nil,
					&snet.Addr{IA: remoteIA, Path: testPath(remoteIF)}, 0)
				res := handler.Handle(req)
				SoMsg("res", res, ShouldEqual, infra.MetricsErrInvalid)
			})
			Convey("Invalid IA", func() {
				req := infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: remoteIF}, nil,
					&snet.Addr{IA: localIA, Path: testPath(localIF)}, 0)
				res := handler.Handle(req)
				SoMsg("res", res, ShouldEqual, infra.MetricsErrInvalid)
			})
		})
	})
}

func initInfos() *ifstate.Infos {
	infoMap := topology.IfInfoMap{localIF: topology.IFInfo{ISD_AS: remoteIA}}
	return ifstate.NewInfos(infoMap, ifstate.Config{})
}

func zeroCallTasks(mctrl *gomock.Controller) StateChangeTasks {
	pusher := mock_keepalive.NewMockIfStatePusher(mctrl)
	beaconer := mock_keepalive.NewMockBeaconer(mctrl)
	dropper := mock_keepalive.NewMockRevDropper(mctrl)

	pusher.EXPECT().Push(gomock.Any()).MaxTimes(0)
	beaconer.EXPECT().Beacon(gomock.Any(), localIF).MaxTimes(0)
	dropper.EXPECT().DeleteRevocation(gomock.Any(), localIA, localIF).MaxTimes(0)
	dropper.EXPECT().DeleteRevocation(gomock.Any(), remoteIA, remoteIF).MaxTimes(0)
	return StateChangeTasks{
		IfStatePusher: pusher,
		Beaconer:      beaconer,
		RevDropper:    dropper,
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
