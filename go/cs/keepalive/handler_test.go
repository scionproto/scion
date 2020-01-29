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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/cs/keepalive/mock_keepalive"
	"github.com/scionproto/scion/go/cs/metrics"
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
	metrics.InitBSMetrics()
	log.Root().SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}

func TestNewHandler(t *testing.T) {
	t.Log("NewHandler creates a correct handler")
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	t.Run("Non-active interface should cause tasks to execute", func(t *testing.T) {
		// The wait group ensures all go routines are finished before the test finishes.
		wg := &sync.WaitGroup{}
		wg.Add(3)
		// Make sure the mock is executed exactly once and updates the waitgroup.
		set := func(call *gomock.Call) *gomock.Call {
			return call.Times(1).Do(func(_ ...interface{}) { wg.Done() })
		}

		pusher := mock_keepalive.NewMockIfStatePusher(mctrl)
		dropper := mock_keepalive.NewMockRevDropper(mctrl)
		set(pusher.EXPECT().Push(gomock.Any(), localIF))
		set(dropper.EXPECT().DeleteRevocation(gomock.Any(), localIA, localIF)).Return(nil)
		set(dropper.EXPECT().DeleteRevocation(gomock.Any(), originIA, originIF)).Return(nil)

		handler := NewHandler(localIA, testInterfaces(t), StateChangeTasks{
			IfStatePusher: pusher,
			RevDropper:    dropper,
		})
		req := infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: originIF}, nil,
			&snet.UDPAddr{IA: originIA, Path: testPath(localIF)}, 0)
		res := handler.Handle(req)
		waitTimeout(t, wg)
		assert.Equal(t, res, infra.MetricsResultOk)

	})

	t.Run("Active interface should cause no tasks to execute", func(t *testing.T) {
		intfs := testInterfaces(t)
		intfs.Get(localIF).Activate(42)
		handler := NewHandler(localIA, intfs, zeroCallTasks(mctrl))
		req := infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: originIF}, nil,
			&snet.UDPAddr{IA: originIA, Path: testPath(localIF)}, 0)
		res := handler.Handle(req)
		assert.Equal(t, res, infra.MetricsResultOk)
	})

	t.Run("Invalid requests cause an error", func(t *testing.T) {
		handler := NewHandler(localIA, testInterfaces(t), zeroCallTasks(mctrl))

		tests := []struct {
			msg string
			req *infra.Request
			exp *infra.HandlerResult
		}{
			{
				msg: "Wrong payload type",
				req: infra.NewRequest(context.Background(), &ctrl.Pld{}, nil,
					&snet.UDPAddr{IA: originIA, Path: testPath(localIF)}, 0),
				exp: infra.MetricsErrInternal,
			},
			{
				msg: "Invalid address type",
				req: infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: originIF}, nil,
					&net.UnixAddr{}, 0),
				exp: infra.MetricsErrInvalid,
			},
			{
				msg: "Invalid path",
				req: infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: originIF}, nil,
					&snet.UDPAddr{IA: originIA, Path: &spath.Path{}}, 0),
				exp: infra.MetricsErrInvalid,
			},
			{
				msg: "Invalid ConsIngress ifid",
				req: infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: originIF}, nil,
					&snet.UDPAddr{IA: originIA, Path: testPath(originIF)}, 0),
				exp: infra.MetricsErrInvalid,
			},
			{
				msg: "Invalid IA",
				req: infra.NewRequest(context.Background(), &ifid.IFID{OrigIfID: originIF}, nil,
					&snet.UDPAddr{IA: localIA, Path: testPath(localIF)}, 0),
				exp: infra.MetricsErrInvalid,
			},
		}

		for _, test := range tests {
			t.Log(test.msg)
			res := handler.Handle(test.req)
			assert.Equal(t, res, test.exp)
		}

	})
}

func testInterfaces(t *testing.T) *ifstate.Interfaces {
	infoMap := topology.IfInfoMap{localIF: topology.IFInfo{IA: originIA}}
	intfs := ifstate.NewInterfaces(infoMap, ifstate.Config{KeepaliveTimeout: time.Nanosecond})
	require.True(t, intfs.Get(localIF).Revoke(), "must revoke interface")
	return intfs
}

func zeroCallTasks(mctrl *gomock.Controller) StateChangeTasks {
	return StateChangeTasks{
		IfStatePusher: mock_keepalive.NewMockIfStatePusher(mctrl),
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

func waitTimeout(t *testing.T, wg *sync.WaitGroup) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-time.After(5 * time.Second):
		assert.Fail(t, "Timed out")
	case <-done:
	}
}
