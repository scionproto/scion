// Copyright 2018 ETH Zurich
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

package snetproxy_test

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet/snetproxy"
)

func TestReconnecterStop(t *testing.T) {
	Convey("Calling stop terminates a reconnect running in the background", t, func() {
		f := func(_ time.Duration) (snetproxy.Conn, error) {
			time.Sleep(10 * time.Millisecond)
			// return dispatcher error s.t. reconnecter reattempts
			return nil, dispatcherError
		}
		reconnecter := snetproxy.NewTickingReconnecter(f)
		barrierCh := make(chan struct{})
		Convey("Stop runs before reconnect runs", func() {
			go func() {
				time.Sleep(10 * time.Millisecond)
				var ignoredTimeout time.Duration
				reconnecter.Reconnect(ignoredTimeout)
			}()
			go func() {
				reconnecter.Stop()
				close(barrierCh)
			}()
			select {
			case <-barrierCh:
			case <-time.After(200 * time.Millisecond):
				t.Fatalf("goroutine took too long to finish")
			}
		})
		Convey("Stop runs after reconnect runs", func() {
			go func() {
				var ignoredTimeout time.Duration
				reconnecter.Reconnect(ignoredTimeout)
				close(barrierCh)
			}()
			go func() {
				time.Sleep(10 * time.Millisecond)
				reconnecter.Stop()
			}()
			select {
			case <-barrierCh:
			case <-time.After(200 * time.Millisecond):
				t.Fatalf("goroutine took too long to finish")
			}
		})
		Convey("Error must be non-nil when timing out due to stop", func() {
			var err error
			go func() {
				time.Sleep(10 * time.Millisecond)
				var ignoredTimeout time.Duration
				_, err = reconnecter.Reconnect(ignoredTimeout)
				close(barrierCh)
			}()
			go func() {
				reconnecter.Stop()
			}()
			select {
			case <-barrierCh:
			case <-time.After(200 * time.Millisecond):
				t.Fatalf("goroutine took too long to finish")
			}
			SoMsg("err", common.GetErrorMsg(err), ShouldEqual, snetproxy.ErrReconnecterStopped)
		})
	})
}
