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
	"context"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/router/bfd"
)

func TestMetrics(t *testing.T) {
	// We only instrument session A
	packetsSent := prometheus.NewCounter(prometheus.CounterOpts{Name: "packets_sent"})
	packetsReceived := prometheus.NewCounter(prometheus.CounterOpts{Name: "packets_received"})
	up := prometheus.NewGauge(prometheus.GaugeOpts{Name: "up"})
	stateChanges := prometheus.NewCounter(prometheus.CounterOpts{Name: "state_changes"})

	sessionA := &bfd.Session{
		DetectMult:            1,
		DesiredMinTxInterval:  200 * time.Millisecond,
		RequiredMinRxInterval: 100 * time.Millisecond,
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
		DesiredMinTxInterval:  200 * time.Millisecond,
		RequiredMinRxInterval: 100 * time.Millisecond,
		LocalDiscriminator:    2,
		ReceiveQueueSize:      10,
	}

	linkAToB := &redirectSender{Destination: sessionB}
	linkBToA := &redirectSender{Destination: sessionA}
	sessionA.Sender = linkAToB
	sessionB.Sender = linkBToA

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		err := sessionA.Run(context.Background())
		require.NoError(t, err)
	}()

	go func() {
		defer wg.Done()
		err := sessionB.Run(context.Background())
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
	betweenOrEqual(t, 5.0, 27.0, promtest.ToFloat64(packetsSent))
	betweenOrEqual(t, 5.0, 27.0, promtest.ToFloat64(packetsReceived))
	assert.Equal(t, 1.0, promtest.ToFloat64(up))
	assert.Greater(t, promtest.ToFloat64(stateChanges), 0.0)

	changes := promtest.ToFloat64(stateChanges)
	linkAToB.Sending(false)
	linkBToA.Sending(false)
	time.Sleep(2 * time.Second)

	assert.Equal(t, 0.0, promtest.ToFloat64(up))
	assert.Greater(t, promtest.ToFloat64(stateChanges), changes)

	linkAToB.Close()
	linkBToA.Close()
	wg.Wait()
}

func betweenOrEqual(t *testing.T, lower, upper, v float64) {
	t.Helper()
	assert.GreaterOrEqual(t, v, lower)
	assert.LessOrEqual(t, v, upper)
}
