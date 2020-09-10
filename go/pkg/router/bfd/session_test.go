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
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/pkg/router/bfd"
)

// redirectSender sends a BFD message directly into a destination Session's receive queue.
type redirectSender struct {
	Destination chan<- *layers.BFD

	mtx        sync.Mutex
	shouldSend bool
}

func (r *redirectSender) Send(bfd *layers.BFD) error {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	// silent discard
	if !r.shouldSend {
		return nil
	}

	// It's fine if we discard messages if the receiving session is slow
	// to drain its channel. The only data point we need is that the
	// sessions under test are up, and this should happen even though
	// some messages may be lost.
	//
	// This can lead to flaky tests when the BFD Detection Multiplier
	// is 1, as a single lost message will take the session down, but
	// that configuration value is best avoided in practice.
	select {
	case r.Destination <- bfd:
	default:
	}
	return nil
}

func (r *redirectSender) Sending(shouldSend bool) {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.shouldSend = shouldSend
}

// Close closes the channel used by the sender.
func (r *redirectSender) Close() {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	// stop sending, to avoid writing any packets still sent by the session to a closed channel.
	r.shouldSend = false
	close(r.Destination)
}

func TestSession(t *testing.T) {
	testCases := map[string]*sessionTestCase{
		"choose desired interval (bootstrapped)": {
			sessionA: &bfd.Session{
				DetectMult:            1,
				DesiredMinTxInterval:  50 * time.Millisecond,
				RequiredMinRxInterval: 25 * time.Millisecond,
				Logger:                log.New(),
				LocalDiscriminator:    1,
				RemoteDiscriminator:   2,
				ReceiveQueueSize:      10,
			},
			sessionB: &bfd.Session{
				DetectMult:            1,
				DesiredMinTxInterval:  50 * time.Millisecond,
				RequiredMinRxInterval: 25 * time.Millisecond,
				Logger:                log.New(),
				LocalDiscriminator:    2,
				RemoteDiscriminator:   1,
				ReceiveQueueSize:      10,
			},
			expectedUpA: true,
			expectedUpB: true,
			testBehavior: func(linkAToB, linkBToA *redirectSender) {
				linkAToB.Sending(true)
				linkBToA.Sending(true)
				time.Sleep(2 * time.Second)
			},
		},
		"choose desired interval (not bootstrapped)": {
			sessionA: &bfd.Session{
				DetectMult:            1,
				DesiredMinTxInterval:  50 * time.Millisecond,
				RequiredMinRxInterval: 25 * time.Millisecond,
				Logger:                log.New(),
				LocalDiscriminator:    1,
				ReceiveQueueSize:      10,
			},
			sessionB: &bfd.Session{
				DetectMult:            1,
				DesiredMinTxInterval:  50 * time.Millisecond,
				RequiredMinRxInterval: 25 * time.Millisecond,
				Logger:                log.New(),
				LocalDiscriminator:    2,
				ReceiveQueueSize:      10,
			},
			expectedUpA: true,
			expectedUpB: true,
			testBehavior: func(linkAToB, linkBToA *redirectSender) {
				linkAToB.Sending(true)
				linkBToA.Sending(true)
				time.Sleep(2 * time.Second)
			},
		},
		"choose required interval (bootstrapped)": {
			sessionA: &bfd.Session{
				DetectMult:            1,
				DesiredMinTxInterval:  25 * time.Millisecond,
				RequiredMinRxInterval: 50 * time.Millisecond,
				Logger:                log.New(),
				LocalDiscriminator:    1,
				RemoteDiscriminator:   2,
				ReceiveQueueSize:      10,
			},
			sessionB: &bfd.Session{
				DetectMult:            1,
				DesiredMinTxInterval:  25 * time.Millisecond,
				RequiredMinRxInterval: 50 * time.Millisecond,
				Logger:                log.New(),
				LocalDiscriminator:    2,
				RemoteDiscriminator:   1,
				ReceiveQueueSize:      10,
			},
			expectedUpA: true,
			expectedUpB: true,
			testBehavior: func(linkAToB, linkBToA *redirectSender) {
				linkAToB.Sending(true)
				linkBToA.Sending(true)
				time.Sleep(2 * time.Second)
			},
		},
		"large detect multiplier, aggressive timers (bootstrapped)": {
			sessionA: &bfd.Session{
				DetectMult:            5,
				DesiredMinTxInterval:  4 * time.Millisecond,
				RequiredMinRxInterval: 2 * time.Millisecond,
				Logger:                log.New(),
				LocalDiscriminator:    1,
				RemoteDiscriminator:   2,
				ReceiveQueueSize:      10,
			},
			sessionB: &bfd.Session{
				DetectMult:            5,
				DesiredMinTxInterval:  4 * time.Millisecond,
				RequiredMinRxInterval: 2 * time.Millisecond,
				Logger:                log.New(),
				LocalDiscriminator:    2,
				RemoteDiscriminator:   1,
				ReceiveQueueSize:      10,
			},
			expectedUpA: true,
			expectedUpB: true,
			testBehavior: func(linkAToB, linkBToA *redirectSender) {
				linkAToB.Sending(true)
				linkBToA.Sending(true)
				time.Sleep(2 * time.Second)
			},
		},
		"link starts ok, goes down (bootstrapped)": {
			sessionA: &bfd.Session{
				DetectMult:            3,
				DesiredMinTxInterval:  10 * time.Millisecond,
				RequiredMinRxInterval: 5 * time.Millisecond,
				Logger:                log.New(),
				LocalDiscriminator:    1,
				RemoteDiscriminator:   2,
				ReceiveQueueSize:      10,
			},
			sessionB: &bfd.Session{
				DetectMult:            3,
				DesiredMinTxInterval:  10 * time.Millisecond,
				RequiredMinRxInterval: 5 * time.Millisecond,
				Logger:                log.New(),
				LocalDiscriminator:    2,
				RemoteDiscriminator:   1,
				ReceiveQueueSize:      10,
			},
			expectedUpA: false,
			expectedUpB: false,
			testBehavior: func(linkAToB, linkBToA *redirectSender) {
				linkAToB.Sending(true)
				linkBToA.Sending(true)
				time.Sleep(2 * time.Second)
				linkAToB.Sending(false)
				linkBToA.Sending(false)
				time.Sleep(time.Second)
			},
		},
		"link starts ok, goes down in one direction (bootstrapped)": {
			sessionA: &bfd.Session{
				DetectMult:            3,
				DesiredMinTxInterval:  10 * time.Millisecond,
				RequiredMinRxInterval: 5 * time.Millisecond,
				Logger:                log.New(),
				LocalDiscriminator:    1,
				RemoteDiscriminator:   2,
				ReceiveQueueSize:      10,
			},
			sessionB: &bfd.Session{
				DetectMult:            3,
				DesiredMinTxInterval:  10 * time.Millisecond,
				RequiredMinRxInterval: 5 * time.Millisecond,
				Logger:                log.New(),
				LocalDiscriminator:    2,
				RemoteDiscriminator:   1,
				ReceiveQueueSize:      10,
			},
			expectedUpA: false,
			expectedUpB: false,
			testBehavior: func(linkAToB, linkBToA *redirectSender) {
				linkAToB.Sending(true)
				linkBToA.Sending(true)
				time.Sleep(2 * time.Second)
				linkAToB.Sending(false)
				time.Sleep(time.Second)
			},
		},
		"link starts ok, goes down, goes up again (bootstrapped)": {
			sessionA: &bfd.Session{
				DetectMult:            3,
				DesiredMinTxInterval:  10 * time.Millisecond,
				RequiredMinRxInterval: 5 * time.Millisecond,
				Logger:                log.New(),
				LocalDiscriminator:    1,
				RemoteDiscriminator:   2,
				ReceiveQueueSize:      10,
			},
			sessionB: &bfd.Session{
				DetectMult:            3,
				DesiredMinTxInterval:  10 * time.Millisecond,
				RequiredMinRxInterval: 5 * time.Millisecond,
				Logger:                log.New(),
				LocalDiscriminator:    2,
				RemoteDiscriminator:   1,
				ReceiveQueueSize:      10,
			},
			expectedUpA: true,
			expectedUpB: true,
			testBehavior: func(linkAToB, linkBToA *redirectSender) {
				linkAToB.Sending(true)
				linkBToA.Sending(true)
				time.Sleep(2 * time.Second)
				linkAToB.Sending(false)
				linkBToA.Sending(false)
				time.Sleep(time.Second)
				linkAToB.Sending(true)
				linkBToA.Sending(true)
				time.Sleep(2 * time.Second)
			},
		},
		"run without logging (bootstrapped)": {
			sessionA: &bfd.Session{
				DetectMult:            1,
				DesiredMinTxInterval:  50 * time.Millisecond,
				RequiredMinRxInterval: 25 * time.Millisecond,
				LocalDiscriminator:    1,
				RemoteDiscriminator:   2,
				ReceiveQueueSize:      10,
			},
			sessionB: &bfd.Session{
				DetectMult:            1,
				DesiredMinTxInterval:  50 * time.Millisecond,
				RequiredMinRxInterval: 25 * time.Millisecond,
				LocalDiscriminator:    2,
				RemoteDiscriminator:   1,
				ReceiveQueueSize:      10,
			},
			expectedUpA: true,
			expectedUpB: true,
			testBehavior: func(linkAToB, linkBToA *redirectSender) {
				linkAToB.Sending(true)
				linkBToA.Sending(true)
				time.Sleep(2 * time.Second)
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, sessionSubtest(name, tc))
	}
}

// sessionSubtest is used to capture the test case data and name for safe parallel execution.
func sessionSubtest(name string, tc *sessionTestCase) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		linkAToB := &redirectSender{Destination: tc.sessionB.Messages()}
		linkBToA := &redirectSender{Destination: tc.sessionA.Messages()}

		tc.sessionA.Sender = linkAToB
		tc.sessionB.Sender = linkBToA

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			err := tc.sessionA.Run()
			require.NoError(t, err)
		}()

		go func() {
			defer wg.Done()
			err := tc.sessionB.Run()
			require.NoError(t, err)
		}()

		tc.testBehavior(linkAToB, linkBToA)

		assert.Equal(t, tc.expectedUpA, tc.sessionA.IsUp())
		assert.Equal(t, tc.expectedUpB, tc.sessionB.IsUp())

		linkAToB.Close()
		linkBToA.Close()
		wg.Wait()
	}
}

func TestSessionDebootstrap(t *testing.T) {
	// This test checks that if a remote session bootstraps against a local session and the local
	// session crashes, the remote session forgets the discriminator it has bootstrapped with. This
	// allows the remote session to bootstrap against a new local discriminator.
	//
	// We check this by having a session A1 be up initially, crashing (simulated by blocking its
	// forwarding), and coming up with a different local discriminator as session A2. We use a
	// controller to demux between A1 and A2, because the controller's demuxing behavior relies
	// on the remote session knowing the correct local discriminator.
	sessionA1 := &bfd.Session{
		DetectMult:            1,
		DesiredMinTxInterval:  50 * time.Millisecond,
		RequiredMinRxInterval: 25 * time.Millisecond,
		Logger:                log.New(),
		LocalDiscriminator:    1234,
		ReceiveQueueSize:      10,
	}
	sessionA2 := &bfd.Session{
		DetectMult:            1,
		DesiredMinTxInterval:  50 * time.Millisecond,
		RequiredMinRxInterval: 25 * time.Millisecond,
		Logger:                log.New(),
		LocalDiscriminator:    4321,
		ReceiveQueueSize:      10,
	}
	sessionB := &bfd.Session{
		DetectMult:            1,
		DesiredMinTxInterval:  50 * time.Millisecond,
		RequiredMinRxInterval: 25 * time.Millisecond,
		Logger:                log.New(),
		LocalDiscriminator:    2,
		ReceiveQueueSize:      10,
	}

	controllerA := &bfd.Controller{
		Sessions:         []*bfd.Session{sessionA1, sessionA2},
		ReceiveQueueSize: 10,
	}

	linkA1ToB := &redirectSender{Destination: sessionB.Messages()}
	linkA2ToB := &redirectSender{Destination: sessionB.Messages()}
	linkBToA := &redirectSender{Destination: controllerA.Messages()}

	sessionA1.Sender = linkA1ToB
	sessionA2.Sender = linkA2ToB
	sessionB.Sender = linkBToA

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		err := controllerA.Run()
		require.NoError(t, err)
	}()

	go func() {
		defer wg.Done()
		err := sessionB.Run()
		require.NoError(t, err)
	}()

	// A1 is the running session, B bootstraps against it. We simulate that A2 "does not exist" yet
	// by not allowing it to forward.
	linkA1ToB.Sending(true)
	linkA2ToB.Sending(false)
	linkBToA.Sending(true)

	time.Sleep(2 * time.Second)

	// A1 is no longer forwarding, simulating a router crash.
	linkA1ToB.Sending(false)

	time.Sleep(time.Second)

	// Router A "restarts", this time A2 starts with a different local discriminator.
	linkA2ToB.Sending(true)

	time.Sleep(2 * time.Second)

	assert.Equal(t, false, sessionA1.IsUp())
	assert.Equal(t, true, sessionA2.IsUp())
	assert.Equal(t, true, sessionB.IsUp())

	linkA2ToB.Sending(false)
	linkA1ToB.Close()
	linkBToA.Close()
	wg.Wait()
}

func TestSessionRun(t *testing.T) {
	testCases := map[string]struct {
		session *bfd.Session
	}{
		"bad detect multiplier": {
			session: &bfd.Session{
				DetectMult:            0,
				DesiredMinTxInterval:  time.Microsecond,
				RequiredMinRxInterval: time.Microsecond,
				LocalDiscriminator:    1,
				RemoteDiscriminator:   2,
				Sender:                &redirectSender{},
			},
		},
		"bad desired min tx interval (0)": {
			session: &bfd.Session{
				DetectMult:            1,
				DesiredMinTxInterval:  time.Microsecond - time.Nanosecond,
				RequiredMinRxInterval: time.Microsecond,
				LocalDiscriminator:    1,
				RemoteDiscriminator:   2,
				Sender:                &redirectSender{},
			},
		},
		"bad desired min tx interval (overflow)": {
			session: &bfd.Session{
				DetectMult:            1,
				DesiredMinTxInterval:  (math.MaxUint32 + 1) * time.Microsecond,
				RequiredMinRxInterval: time.Microsecond,
				LocalDiscriminator:    1,
				RemoteDiscriminator:   2,
				Sender:                &redirectSender{},
			},
		},
		"bad required min rx interval (0)": {
			session: &bfd.Session{
				DetectMult:            1,
				DesiredMinTxInterval:  time.Microsecond,
				RequiredMinRxInterval: time.Microsecond - time.Nanosecond,
				LocalDiscriminator:    1,
				RemoteDiscriminator:   2,
				Sender:                &redirectSender{},
			},
		},
		"bad required min rx interval (overflow)": {
			session: &bfd.Session{
				DetectMult:            1,
				DesiredMinTxInterval:  time.Microsecond,
				RequiredMinRxInterval: (math.MaxUint32 + 1) * time.Microsecond,
				LocalDiscriminator:    1,
				RemoteDiscriminator:   2,
				Sender:                &redirectSender{},
			},
		},
		"bad local discriminator": {
			session: &bfd.Session{
				DetectMult:            1,
				DesiredMinTxInterval:  time.Microsecond,
				RequiredMinRxInterval: time.Microsecond,
				LocalDiscriminator:    0,
				RemoteDiscriminator:   2,
				Sender:                &redirectSender{},
			},
		},
		"bad sender": {
			session: &bfd.Session{
				DetectMult:            1,
				DesiredMinTxInterval:  time.Microsecond,
				RequiredMinRxInterval: time.Microsecond,
				LocalDiscriminator:    1,
				RemoteDiscriminator:   2,
				Sender:                nil,
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, tc.session.Run())
		})
	}
}

func TestSessionRunMultiple(t *testing.T) {
	session := &bfd.Session{
		DetectMult:            1,
		DesiredMinTxInterval:  time.Microsecond,
		RequiredMinRxInterval: time.Microsecond,
		LocalDiscriminator:    1,
		RemoteDiscriminator:   2,
		Sender:                &redirectSender{},
	}

	// we can close messages before the session has executed, and it will start and then
	// immediately shut down cleanly.
	close(session.Messages())

	err := session.Run()
	require.NoError(t, err)
	err = session.Run()
	assert.Error(t, err)
}

func TestSessionRunInit(t *testing.T) {
	// Test that if Run is called without a prior call to method Messages it does not deadlock.
	session := &bfd.Session{
		DetectMult:            1,
		DesiredMinTxInterval:  time.Microsecond,
		RequiredMinRxInterval: time.Microsecond,
		LocalDiscriminator:    1,
		RemoteDiscriminator:   2,
		Sender:                &redirectSender{},
		Logger:                log.New(),
	}

	barrier := make(chan struct{})

	go func() {
		err := session.Run()
		assert.NoError(t, err)
		close(barrier)
	}()

	time.Sleep(200 * time.Millisecond)
	close(session.Messages())

	select {
	case <-barrier:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("Run did not finish in time")
	}
}

func TestPrintPacket(t *testing.T) {
	testCases := []*struct {
		packet         *layers.BFD
		expectedString string
	}{
		{
			packet:         nil,
			expectedString: "<nil>",
		},
		{
			packet: &layers.BFD{
				MyDiscriminator:       10,
				YourDiscriminator:     20,
				DesiredMinTxInterval:  1000000,
				RequiredMinRxInterval: 1000,
			},
			expectedString: "MyDisc: 10, YourDisc: 20, State: Admin Down, DesMinTX: 1s, " +
				"ReqMinRX: 1ms",
		},
		{
			packet: &layers.BFD{
				MyDiscriminator:       10,
				YourDiscriminator:     20,
				DesiredMinTxInterval:  1000001,
				RequiredMinRxInterval: 1001,
			},
			expectedString: "MyDisc: 10, YourDisc: 20, State: Admin Down, DesMinTX: 1.000001s, " +
				"ReqMinRX: 1.001ms",
		},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.expectedString, bfd.PrintPacket(tc.packet))
	}
}

func TestShouldDiscard(t *testing.T) {
	validPacketTemplate := layers.BFD{
		Version:                   1,
		Diagnostic:                0,
		State:                     layers.BFDStateDown,
		Poll:                      false,
		Final:                     false,
		ControlPlaneIndependent:   false,
		AuthPresent:               false,
		Demand:                    false,
		Multipoint:                false,
		DetectMultiplier:          1,
		MyDiscriminator:           1,
		YourDiscriminator:         2,
		DesiredMinTxInterval:      1000000,
		RequiredMinRxInterval:     1000000,
		RequiredMinEchoRxInterval: 0,
		AuthHeader:                nil,
	}
	discard, reason := bfd.ShouldDiscard(bfd.StateUp, &validPacketTemplate)
	require.False(t, discard)
	require.Empty(t, reason)

	testCases := map[string]*struct {
		packetEdit    func(layers.BFD) layers.BFD
		localState    bfd.State
		shouldDiscard bool
		hasReason     assert.ValueAssertionFunc
	}{
		"bad version": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.Version = 3
				return pkt
			},
			localState:    bfd.StateUp,
			shouldDiscard: true,
			hasReason:     assert.Empty,
		},
		"bad detect multiplier": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.DetectMultiplier = 0
				return pkt
			},
			localState:    bfd.StateUp,
			shouldDiscard: true,
			hasReason:     assert.Empty,
		},
		"bad multipoint bit": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.Multipoint = true
				return pkt
			},
			localState:    bfd.StateUp,
			shouldDiscard: true,
			hasReason:     assert.Empty,
		},
		"bad my discriminator": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.MyDiscriminator = 0
				return pkt
			},
			localState:    bfd.StateUp,
			shouldDiscard: true,
			hasReason:     assert.Empty,
		},
		"bad your discriminator, up state": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.YourDiscriminator = 0
				return pkt
			},
			localState:    bfd.StateUp,
			shouldDiscard: true,
			hasReason:     assert.Empty,
		},
		"good your discriminator, down state": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.YourDiscriminator = 0
				return pkt
			},
			localState:    bfd.StateDown,
			shouldDiscard: false,
			hasReason:     assert.Empty,
		},
		"good your discriminator, admin down state": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.YourDiscriminator = 0
				return pkt
			},
			localState:    bfd.StateDown,
			shouldDiscard: false,
			hasReason:     assert.Empty,
		},
		"auth set, nil header": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.AuthPresent = true
				pkt.AuthHeader = nil
				return pkt
			},
			localState:    bfd.StateUp,
			shouldDiscard: true,
			hasReason:     assert.Empty,
		},
		"auth set, auth type none": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.AuthPresent = true
				pkt.AuthHeader = &layers.BFDAuthHeader{
					AuthType: layers.BFDAuthTypeNone,
				}
				return pkt
			},
			localState:    bfd.StateUp,
			shouldDiscard: true,
			hasReason:     assert.Empty,
		},
		"auth set, auth type md5": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.AuthPresent = true
				pkt.AuthHeader = &layers.BFDAuthHeader{
					AuthType: layers.BFDAuthTypeKeyedMD5,
				}
				return pkt
			},
			localState:    bfd.StateUp,
			shouldDiscard: true,
			// This is a valid RFC 5880 combination, but we discard this because the
			// implementation doesn't support it yet.
			hasReason: assert.NotEmpty,
		},
		"auth clear, no auth header": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.AuthPresent = false
				pkt.AuthHeader = nil
				return pkt
			},
			localState:    bfd.StateUp,
			shouldDiscard: false,
			hasReason:     assert.Empty,
		},
		"auth clear, auth type none": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.AuthPresent = false
				pkt.AuthHeader = &layers.BFDAuthHeader{
					AuthType: layers.BFDAuthTypeNone,
				}
				return pkt
			},
			localState:    bfd.StateUp,
			shouldDiscard: false,
			hasReason:     assert.Empty,
		},
		"auth clear, auth type md5": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.AuthPresent = false
				pkt.AuthHeader = &layers.BFDAuthHeader{
					AuthType: layers.BFDAuthTypeKeyedMD5,
				}
				return pkt
			},
			localState:    bfd.StateUp,
			shouldDiscard: true,
			hasReason:     assert.Empty,
		},
		"poll bit set": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.Poll = true
				return pkt
			},
			localState:    bfd.StateUp,
			shouldDiscard: true,
			hasReason:     assert.NotEmpty,
		},
		"final bit set": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.Final = true
				return pkt
			},
			localState:    bfd.StateUp,
			shouldDiscard: true,
			hasReason:     assert.NotEmpty,
		},
		"echo function enabled": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.RequiredMinEchoRxInterval = 1
				return pkt
			},
			localState:    bfd.StateUp,
			shouldDiscard: true,
			hasReason:     assert.NotEmpty,
		},
		"demand bit set": {
			packetEdit: func(pkt layers.BFD) layers.BFD {
				pkt.Demand = true
				return pkt
			},
			localState:    bfd.StateUp,
			shouldDiscard: true,
			hasReason:     assert.NotEmpty,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			pkt := tc.packetEdit(validPacketTemplate)
			shouldDiscard, reason := bfd.ShouldDiscard(tc.localState, &pkt)
			assert.Equal(t, tc.shouldDiscard, shouldDiscard)
			tc.hasReason(t, reason)
		})
	}
}

func TestDurationToBFDInterval(t *testing.T) {
	testCases := []*struct {
		duration         time.Duration
		expectedInterval layers.BFDTimeInterval
		expectedError    assert.ErrorAssertionFunc
	}{
		{
			duration:         0,
			expectedInterval: 0,
			expectedError:    assert.NoError,
		},
		{
			duration:         -1,
			expectedInterval: 0,
			expectedError:    assert.Error,
		},
		{
			duration:         time.Microsecond,
			expectedInterval: 1,
			expectedError:    assert.NoError,
		},
		{
			duration:         0,
			expectedInterval: 0,
			expectedError:    assert.NoError,
		},
		{
			duration:         time.Microsecond - time.Nanosecond,
			expectedInterval: 0,
			expectedError:    assert.NoError,
		},
		{
			duration:         time.Microsecond + time.Nanosecond,
			expectedInterval: 1,
			expectedError:    assert.NoError,
		},
		{
			duration:         time.Second,
			expectedInterval: 1000000,
			expectedError:    assert.NoError,
		},
		{
			duration:         math.MaxUint32 * time.Microsecond,
			expectedInterval: math.MaxUint32,
			expectedError:    assert.NoError,
		},
		{
			duration:         (math.MaxUint32 + 1) * time.Microsecond,
			expectedInterval: 0,
			expectedError:    assert.Error,
		},
	}

	for i, tc := range testCases {
		interval, err := bfd.DurationToBFDInterval(tc.duration)
		assert.Equal(t, tc.expectedInterval, interval, fmt.Sprintf("test case %d (%+v)", i, tc))
		tc.expectedError(t, err)
	}

}

func TestBFDIntervalToDuration(t *testing.T) {
	testCases := []*struct {
		bfdInterval      layers.BFDTimeInterval
		expectedDuration time.Duration
	}{
		{
			bfdInterval:      0,
			expectedDuration: 0,
		},
		{
			bfdInterval:      1000,
			expectedDuration: time.Millisecond,
		},
	}

	for i, tc := range testCases {
		assert.Equal(t, tc.expectedDuration, bfd.BFDIntervalToDuration(tc.bfdInterval),
			"test case %d (%+v)", i, tc)
	}
}
