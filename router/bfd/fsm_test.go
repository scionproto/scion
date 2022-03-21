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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/pkg/router/bfd"
)

func TestTransition(t *testing.T) {
	t.Run("normal transitions", func(t *testing.T) {
		testCases := []struct {
			currState bfd.State
			Event     bfd.Event
			wantState bfd.State
		}{
			{currState: bfd.StateInit, Event: bfd.EventInit, wantState: bfd.StateUp},
			{currState: bfd.StateInit, Event: bfd.EventDown, wantState: bfd.StateInit},
			{currState: bfd.StateInit, Event: bfd.EventUp, wantState: bfd.StateUp},
			{currState: bfd.StateInit, Event: bfd.EventTimer, wantState: bfd.StateDown},
			{currState: bfd.StateInit, Event: bfd.EventAdminDown, wantState: bfd.StateAdminDown},
			{currState: bfd.StateInit, Event: bfd.EventAdminUp, wantState: bfd.StateInit},
			{currState: bfd.StateDown, Event: bfd.EventInit, wantState: bfd.StateUp},
			{currState: bfd.StateDown, Event: bfd.EventDown, wantState: bfd.StateInit},
			{currState: bfd.StateDown, Event: bfd.EventUp, wantState: bfd.StateDown},
			{currState: bfd.StateDown, Event: bfd.EventTimer, wantState: bfd.StateDown},
			{currState: bfd.StateDown, Event: bfd.EventAdminDown, wantState: bfd.StateAdminDown},
			{currState: bfd.StateDown, Event: bfd.EventAdminUp, wantState: bfd.StateDown},
			{currState: bfd.StateUp, Event: bfd.EventInit, wantState: bfd.StateUp},
			{currState: bfd.StateUp, Event: bfd.EventDown, wantState: bfd.StateDown},
			{currState: bfd.StateUp, Event: bfd.EventUp, wantState: bfd.StateUp},
			{currState: bfd.StateUp, Event: bfd.EventTimer, wantState: bfd.StateDown},
			{currState: bfd.StateUp, Event: bfd.EventAdminDown, wantState: bfd.StateAdminDown},
			{currState: bfd.StateUp, Event: bfd.EventAdminUp, wantState: bfd.StateUp},
			{currState: bfd.StateAdminDown, Event: bfd.EventInit, wantState: bfd.StateAdminDown},
			{currState: bfd.StateAdminDown, Event: bfd.EventDown, wantState: bfd.StateAdminDown},
			{currState: bfd.StateAdminDown, Event: bfd.EventUp, wantState: bfd.StateAdminDown},
			{currState: bfd.StateAdminDown, Event: bfd.EventTimer, wantState: bfd.StateAdminDown},
			{
				currState: bfd.StateAdminDown,
				Event:     bfd.EventAdminDown,
				wantState: bfd.StateAdminDown,
			},
			{currState: bfd.StateAdminDown, Event: bfd.EventAdminUp, wantState: bfd.StateDown},
		}

		for _, tc := range testCases {
			assert.Equal(t, tc.wantState, bfd.Transition(tc.currState, tc.Event),
				fmt.Sprintf("bad transition from state %v on event %v", tc.currState, tc.Event))
		}
	})

	t.Run("panic on bad event", func(t *testing.T) {
		testCases := []bfd.State{
			bfd.StateAdminDown,
			bfd.StateDown,
			bfd.StateUp,
			bfd.StateInit,
		}
		for _, tc := range testCases {
			assert.Panics(t, func() { bfd.Transition(tc, bfd.Event(1337)) },
				fmt.Sprintf("expected panic on transition from state %v on bad event", tc))
		}
	})

	t.Run("panic on bad state", func(t *testing.T) {
		testCases := []bfd.Event{
			bfd.EventInit,
			bfd.EventTimer,
			bfd.EventUp,
			bfd.EventDown,
			bfd.EventAdminUp,
			bfd.EventAdminDown,
		}
		for _, tc := range testCases {
			assert.Panics(t, func() { bfd.Transition(bfd.State(73), tc) },
				fmt.Sprintf("expected panic on transition from bad state on event %v", tc))
		}
	})
}

func TestStateString(t *testing.T) {
	// Check that our type also prints the unknown integer value
	assert.Equal(t, "Unknown (73)", bfd.State(73).String())
}

func TestEventString(t *testing.T) {
	testCases := []*struct {
		event    bfd.Event
		expected string
	}{
		{event: bfd.EventAdminDown, expected: "Admin down"},
		{event: bfd.EventDown, expected: "Down"},
		{event: bfd.EventInit, expected: "Init"},
		{event: bfd.EventUp, expected: "Up"},
		{event: bfd.EventTimer, expected: "Timer"},
		{event: bfd.EventAdminUp, expected: "Admin up"},
		{event: bfd.Event(73), expected: "Unknown (73)"},
	}

	for i, tc := range testCases {
		assert.Equal(t, tc.expected, tc.event.String(), fmt.Sprintf("test case %d (%v)", i, tc))
	}
}
