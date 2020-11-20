// Copyright 2020 Anapaya Systems

package control_test

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/gateway/control"
	"github.com/scionproto/scion/go/pkg/gateway/control/mock_control"
	"github.com/scionproto/scion/go/pkg/gateway/pathhealth"
)

func TestSessionRun(t *testing.T) {
	t.Run("0 poll interval", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		path := mock_snet.NewMockPath(ctrl)
		pathMonitorRegistration := mock_control.NewMockPathMonitorRegistration(ctrl)
		// Session will have a polling interval of 0, and we'll push only one Up transition to it,
		// so it will query the path monitor exactly once.
		pathMonitorRegistration.EXPECT().Get().Return(
			pathhealth.Selection{Paths: []snet.Path{path}},
		)

		dataplaneSession := mock_control.NewMockDataplaneSession(ctrl)
		dataplaneSession.EXPECT().SetPath(path)

		events := make(chan control.SessionEvent)
		sessionMonitorEvents := make(chan control.SessionEvent)

		session := &control.Session{
			Events:                  events,
			SessionMonitorEvents:    sessionMonitorEvents,
			PathMonitorRegistration: pathMonitorRegistration,
			DataplaneSession:        dataplaneSession,
		}

		done := make(chan struct{})
		go func() {
			err := session.Run()
			assert.NoError(t, err)
			close(done)
		}()

		// Send up event, check that session forwards it
		select {
		case sessionMonitorEvents <- control.SessionEvent{Event: control.EventUp, SessionID: 1}:
		case <-time.After(time.Second):
			t.Fatal("test deadline exceeded while sending Up event notification")
		}
		select {
		case event := <-events:
			assert.Equal(t, control.SessionEvent{Event: control.EventUp, SessionID: 1}, event)
		case <-time.After(time.Second):
			t.Fatal("test deadline exceeded while waiting for Up event notification")
		}

		// Send down event, check that session forwards it
		select {
		case sessionMonitorEvents <- control.SessionEvent{Event: control.EventDown, SessionID: 1}:
		case <-time.After(time.Second):
			t.Fatal("test deadline exceeded while sending Down event notification")
		}
		select {
		case event := <-events:
			assert.Equal(
				t,
				control.SessionEvent{Event: control.EventDown, SessionID: 1},
				event,
			)
		case <-time.After(time.Second):
			t.Fatal("test deadline exceeded while waiting for event notification")
		}

		// Close session monitor event channel and check that the session closes down
		close(sessionMonitorEvents)
		xtest.AssertReadReturnsBefore(t, done, time.Second)
	})

	t.Run("50ms poll interval", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		path := mock_snet.NewMockPath(ctrl)
		pathMonitorRegistration := mock_control.NewMockPathMonitorRegistration(ctrl)
		// Test will run for 200ms, estimate that at least two polls succeed.
		pathMonitorRegistration.EXPECT().Get().Return(pathhealth.Selection{
			Paths: []snet.Path{path}}).MinTimes(2)

		dataplaneSession := mock_control.NewMockDataplaneSession(ctrl)
		dataplaneSession.EXPECT().SetPath(path).MinTimes(2)

		events := make(chan control.SessionEvent)
		sessionMonitorEvents := make(chan control.SessionEvent)

		session := &control.Session{
			Events:                  events,
			SessionMonitorEvents:    sessionMonitorEvents,
			PathMonitorRegistration: pathMonitorRegistration,
			PathMonitorPollInterval: 50 * time.Millisecond,
			DataplaneSession:        dataplaneSession,
		}

		done := make(chan struct{})
		go func() {
			err := session.Run()
			assert.NoError(t, err)
			close(done)
		}()

		time.Sleep(200 * time.Millisecond)

		// Close session monitor event channel and check that the session closes down
		close(sessionMonitorEvents)
		xtest.AssertReadReturnsBefore(t, done, time.Second)
	})
}
