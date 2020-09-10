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
	"github.com/scionproto/scion/go/pkg/router/bfd"
)

func TestControllerRun(t *testing.T) {
	testCases := map[string]*sessionTestCase{
		"state is up": {
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
			testBehavior: func(messageQueue, _ *redirectSender) {
				messageQueue.Sending(true)
				time.Sleep(2 * time.Second)
			},
		},
		"state is down": {
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
			expectedUpA: false,
			expectedUpB: false,
			testBehavior: func(messageQueue, _ *redirectSender) {
				time.Sleep(2 * time.Second)
			},
		},
		"state is down (session not found)": {
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
				// mismatch in discriminators will cause controller to drop BFD messages
				LocalDiscriminator:  3,
				RemoteDiscriminator: 1,
				ReceiveQueueSize:    10,
			},
			expectedUpA: false,
			expectedUpB: false,
			testBehavior: func(messageQueue, _ *redirectSender) {
				messageQueue.Sending(true)
				time.Sleep(2 * time.Second)
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, controllerSubtest(name, tc))
	}
}

// controllerSubtest is used to capture the test case data and name for safe parallel execution.
func controllerSubtest(name string, tc *sessionTestCase) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		// This test uses the same controller to manage two sessions that are communicating with
		// each other (basically, both the "local" and "remote" session are on the same system).
		// This is possible because the local discriminators are chosen such that they are
		// different.
		//
		// While this is something that rarely (if ever) occurs in practice, it makes test setup
		// much simpler here. In the real world, BFD would configured between two systems and each
		// system would have its own controller which is in charge only of sessions on that system.
		controller := &bfd.Controller{
			Sessions:         []*bfd.Session{tc.sessionA, tc.sessionB},
			ReceiveQueueSize: 10,
		}

		// both sessions send their messages through the same controller
		messageQueue := &redirectSender{Destination: controller.Messages()}
		tc.sessionA.Sender = messageQueue
		tc.sessionB.Sender = messageQueue

		// the wait group is not used for synchronization, but rather to check that the controller
		// returns
		var wg sync.WaitGroup
		wg.Add(1)

		go func() {
			err := controller.Run()
			require.NoError(t, err)
			wg.Done()
		}()

		// second argument is not used because we have a single queue
		tc.testBehavior(messageQueue, nil)

		assert.Equal(t, tc.expectedUpA, controller.IsUp(tc.sessionA.LocalDiscriminator))
		assert.Equal(t, tc.expectedUpB, controller.IsUp(tc.sessionB.LocalDiscriminator))

		messageQueue.Close()

		for i := 0; i < 2; i++ {
			err := <-controller.Errors()
			assert.NoError(t, err)
		}
		wg.Wait()
	}
}

func TestControllerBadSession(t *testing.T) {
	// Test for sessions that will error out when running.
	controller := &bfd.Controller{
		Sessions: []*bfd.Session{
			{
				DetectMult:            0, // causes session to error out
				DesiredMinTxInterval:  50 * time.Millisecond,
				RequiredMinRxInterval: 25 * time.Millisecond,
				Logger:                log.New(),
				LocalDiscriminator:    1,
				ReceiveQueueSize:      10,
			},
		},
	}

	go func() {
		err := controller.Run()
		assert.NoError(t, err)
	}()

	err := <-controller.Errors()
	assert.Error(t, err)

	close(controller.Messages())
}

func TestControllerBadInitialization(t *testing.T) {
	// Test for sessions with invalid data that will make the controller fail at start-up.
	testCases := map[string]struct {
		sessions []*bfd.Session
	}{
		"nil": {
			sessions: []*bfd.Session{nil},
		},
		"duplicate local discriminator": {
			sessions: []*bfd.Session{
				{LocalDiscriminator: 10},
				{LocalDiscriminator: 10},
			},
		},
		"zero local discriminator": {
			sessions: []*bfd.Session{
				{},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			controller := &bfd.Controller{
				Sessions: tc.sessions,
			}
			err := controller.Run()
			assert.Error(t, err)
		})
	}
}

func TestControllerRunInit(t *testing.T) {
	// Test that if Run is called without a prior call to method Messages or Errors, it does not
	// deadlock.
	session := &bfd.Session{
		DetectMult:            1,
		DesiredMinTxInterval:  time.Microsecond,
		RequiredMinRxInterval: time.Microsecond,
		LocalDiscriminator:    1,
		RemoteDiscriminator:   2,
		Sender:                &redirectSender{},
		Logger:                log.New(),
	}

	controller := &bfd.Controller{
		Sessions: []*bfd.Session{session},
	}

	barrier := make(chan struct{})

	go func() {
		err := controller.Run()
		assert.NoError(t, err)
		close(barrier)
	}()

	time.Sleep(200 * time.Millisecond)
	close(controller.Messages())

	select {
	case <-barrier:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("Run did not finish in time")
	}
}
