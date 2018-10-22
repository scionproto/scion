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
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/snetproxy"
	"github.com/scionproto/scion/go/lib/xtest"
)

// newErrorReconnF returns a dispatcher error after the duration elapses.
func newErrorReconnF(sleep time.Duration) func(time.Duration) (snet.Conn, error) {
	return func(_ time.Duration) (snet.Conn, error) {
		time.Sleep(sleep)
		// return dispatcher error s.t. reconnecter reattempts
		return nil, dispatcherError
	}
}

func TestTickingReconnectorStop(t *testing.T) {
	Convey("Calling stop terminates a reconnect running in the background", t, func() {
		reconnecter := snetproxy.NewTickingReconnecter(newErrorReconnF(tickerMultiplier(1)))
		barrierCh := make(chan struct{})
		Convey("Stop returns immediately if a reconnect is not running", func() {
			go func() {
				stopAfter(reconnecter, 0)
				close(barrierCh)
			}()
			xtest.AssertReadReturnsBefore(t, barrierCh, tickerMultiplier(2))
		})
		Convey("Stop causes reconnect to return right after the current attempt finishes", func() {
			// Note that because it is not possible right now to interrupt the
			// listen/dial step of a reconnection, the soonest we can return
			// after a Stop() is after the next Listen/Dial returns
			go func() {
				reconnectWithoutTimeoutAfter(reconnecter, 0)
				close(barrierCh)
			}()
			go stopAfter(reconnecter, tickerMultiplier(1))
			xtest.AssertReadReturnsBefore(t, barrierCh, tickerMultiplier(4))
		})
		Convey("Error must be non-nil when timing out due to stop", func() {
			var err error
			go func() {
				err = reconnectWithoutTimeoutAfter(reconnecter, tickerMultiplier(1))
				close(barrierCh)
			}()
			go reconnecter.Stop()
			xtest.AssertReadReturnsBefore(t, barrierCh, tickerMultiplier(4))
			SoMsg("err", common.GetErrorMsg(err), ShouldEqual, snetproxy.ErrReconnecterStopped)
		})
	})
	Convey("Given a reconnection function that takes a long time", t, func() {
		reconnecter := snetproxy.NewTickingReconnecter(newErrorReconnF(tickerMultiplier(4)))
		barrierCh := make(chan struct{})
		Convey("Stop waits for a running reconnection attempt to finish before returning", func() {
			go func() {
				reconnectWithoutTimeoutAfter(reconnecter, 0)
			}()
			go func() {
				stopAfter(reconnecter, tickerMultiplier(1))
				close(barrierCh)
			}()
			xtest.AssertReadReturnsBetween(t, barrierCh, tickerMultiplier(3), tickerMultiplier(8))
		})
	})
}

func reconnectWithoutTimeoutAfter(reconnecter *snetproxy.TickingReconnecter,
	sleepAtStart time.Duration) error {

	time.Sleep(sleepAtStart)
	_, err := reconnecter.Reconnect(0)
	return err
}

func stopAfter(reconnecter *snetproxy.TickingReconnecter, sleepAtStart time.Duration) {
	time.Sleep(sleepAtStart)
	reconnecter.Stop()
}
