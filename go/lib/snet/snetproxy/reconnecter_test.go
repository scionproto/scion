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

	"github.com/scionproto/scion/go/lib/snet/snetproxy"
)

func TestReconnecterStop(t *testing.T) {
	Convey("Calling stop terminates a reconnect running in the background", t, func() {
		f := func(_ time.Duration) (snetproxy.Conn, error) {
			time.Sleep(tickerMultiplier(1))
			// return dispatcher error s.t. reconnecter reattempts
			return nil, dispatcherError
		}
		reconnecter := snetproxy.NewTickingReconnecter(f)
		barrierCh := make(chan struct{})
		Convey("Stop runs before reconnect runs", func() {
			go reconnectAfter(reconnecter, tickerMultiplier(1))
			go func() {
				stopAfter(reconnecter, 0)
				close(barrierCh)
			}()
			assertChannelClosedBefore(t, barrierCh, tickerMultiplier(20))
		})
		Convey("Stop runs after reconnect runs", func() {
			go func() {
				reconnectAfter(reconnecter, 0)
				close(barrierCh)
			}()
			go stopAfter(reconnecter, tickerMultiplier(1))
			assertChannelClosedBefore(t, barrierCh, tickerMultiplier(20))
		})
		Convey("Error must be non-nil when timing out due to stop", func() {
			var err error
			go func() {
				err = reconnectAfter(reconnecter, tickerMultiplier(1))
				close(barrierCh)
			}()
			go reconnecter.Stop()
			assertChannelClosedBefore(t, barrierCh, tickerMultiplier(20))
		})
	})
}

func reconnectAfter(reconnecter *snetproxy.TickingReconnecter, sleepAtStart time.Duration) error {
	time.Sleep(sleepAtStart)
	_, err := reconnecter.Reconnect(0)
	return err
}

func stopAfter(reconnecter *snetproxy.TickingReconnecter, sleepAtStart time.Duration) {
	time.Sleep(sleepAtStart)
	reconnecter.Stop()
}

func assertChannelClosedBefore(t *testing.T, ch <-chan struct{}, timeout time.Duration) {
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatalf("goroutine took too long to finish")
	}
}
