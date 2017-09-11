// Copyright 2017 ETH Zurich
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

package hello

import (
	"time"

	"github.com/prometheus/common/log"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/snet"
)

const (
	DefaultTimeout = 500 * time.Millisecond
	// After this many consecutive hello failures run Down() event
	DownFailureCount = 3
)

type Callback func()

func EchoClient(m *Mux, raddr *snet.Addr, onDown, onUp Callback) {
	isUp := true
	failures := 0
	channels := m.AddRemote(raddr.IA)

	timer := time.NewTimer(DefaultTimeout)
	// Drain channel to safely Reset timer on start of loop
	<-timer.C
	for {
		if failures == DownFailureCount {
			log.Error("Ctrl module marked remote as down", "remote", ia)
			onDown()
			isUp = false
		}

		// timer.C is always drained before getting here, so Reset is race free
		timer.Reset(DefaultTimeout)
		msg := Msg{
			Raddr:   raddr,
			Payload: make(common.RawBytes, 0),
		}
		select {
		case channels.Out <- msg:
		case <-timer.C:
			failures++
			log.Warn("Ctrl timed out waiting to send echo", "remote", ia)
			continue
		}
		select {
		case <-channels.In:
			// Don't care if we receive older reply, as long as we receive something
		case <-timer.C:
			failures++
			log.Warn("Ctrl timed out waiting to receive echo reply", "remote", ia)
			continue
		}

		failures = 0
		if isUp == false {
			log.Info("Ctrl module marked remote as up", "remote", ia)
			onUp()
			isUp = true
		}
		<-timer.C
	}
}
