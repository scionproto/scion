// Copyright 2020 Anapaya Systems
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

package bfd_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/pkg/router/bfd"
)

func TestMetrics(t *testing.T) {
	// We only instrument session A
	packetsSent := metrics.NewTestCounter()
	packetsReceived := metrics.NewTestCounter()
	up := metrics.NewTestGauge()
	stateChanges := metrics.NewTestCounter()

	sessionA := &bfd.Session{
		DetectMult:            1,
		DesiredMinTxInterval:  50 * time.Millisecond,
		RequiredMinRxInterval: 25 * time.Millisecond,
		Logger:                log.New(),
		LocalDiscriminator:    1,
		ReceiveQueueSize:      10,
		Metrics: bfd.Metrics{
			PacketsSent:     packetsSent,
			PacketsReceived: packetsReceived,
			Up:              up,
			StateChanges:    stateChanges,
		},
	}

	sessionB := &bfd.Session{
		DetectMult:            1,
		DesiredMinTxInterval:  50 * time.Millisecond,
		RequiredMinRxInterval: 25 * time.Millisecond,
		Logger:                log.New(),
		LocalDiscriminator:    2,
		ReceiveQueueSize:      10,
	}

	linkAToB := &redirectSender{Destination: sessionB.Messages()}
	linkBToA := &redirectSender{Destination: sessionA.Messages()}
	sessionA.Sender = linkAToB
	sessionB.Sender = linkBToA

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		err := sessionA.Run()
		require.NoError(t, err)
	}()

	go func() {
		defer wg.Done()
		err := sessionB.Run()
		require.NoError(t, err)
	}()

	linkAToB.Sending(true)
	linkBToA.Sending(true)
	time.Sleep(2 * time.Second)

	// 2 second test:
	//  - 1 second is the initial setup (due to the 1 second interval recommended by
	//    the RFC is a session is down)
	//  - 1 seconds is for the test
	// Negotiation of send interval should yield 50 millis, with jitter adjusment that can be as
	// fast as 37.5 millis, so that gives an upper bound of approximately 27 packets and lower bound
	// of 10. For flakyness, we expect between 5 and 27.
	betweenOrEqual(t, 5.0, 27.0, metrics.CounterValue(packetsSent))
	betweenOrEqual(t, 5.0, 27.0, metrics.CounterValue(packetsReceived))
	assert.Equal(t, 1.0, metrics.GaugeValue(up))
	assert.Greater(t, metrics.CounterValue(stateChanges), 0.0)

	changes := metrics.CounterValue(stateChanges)
	linkAToB.Sending(false)
	linkBToA.Sending(false)
	time.Sleep(2 * time.Second)

	assert.Equal(t, 0.0, metrics.GaugeValue(up))
	assert.Greater(t, metrics.CounterValue(stateChanges), changes)

	linkAToB.Close()
	linkBToA.Close()
	wg.Wait()
}

func betweenOrEqual(t *testing.T, lower, upper, v float64) {
	t.Helper()
	assert.GreaterOrEqual(t, v, lower)
	assert.LessOrEqual(t, v, upper)
}
