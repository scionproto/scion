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

package bfd

import (
	"fmt"

	"github.com/gopacket/gopacket/layers"
)

// state describes a BFD state machine state.
//
// The state machine is defined in RFC 5880 as:
//
//	                          +--+
//	                          |  | UP, ADMIN DOWN, TIMER
//	                          |  V
//	                  DOWN  +------+  INIT
//	           +------------|      |------------+
//	           |            | DOWN |            |
//	           |  +-------->|      |<--------+  |
//	           |  |         +------+         |  |
//	           |  |                          |  |
//	           |  |               ADMIN DOWN,|  |
//	           |  |ADMIN DOWN,          DOWN,|  |
//	           |  |TIMER                TIMER|  |
//	           V  |                          |  V
//	         +------+                      +------+
//	    +----|      |                      |      |----+
//	DOWN|    | INIT |--------------------->|  UP  |    |INIT, UP
//	    +--->|      | INIT, UP             |      |<---+
//	         +------+                      +------+
//
// This package implements the full-state machine, including a separate
// state for Admin Down.
type state layers.BFDState

// BFD state machine states as defined in RFC 5880.
const (
	stateInit      = state(layers.BFDStateInit)
	stateDown      = state(layers.BFDStateDown)
	stateUp        = state(layers.BFDStateUp)
	stateAdminDown = state(layers.BFDStateAdminDown)
)

// String is the same as the BFD layer state String method, except it prints
// the integer value of the state when it is unknown.
func (s state) String() string {
	x := layers.BFDState(s)
	if x == layers.BFDStateUp || x == layers.BFDStateDown || x == layers.BFDStateAdminDown ||
		x == layers.BFDStateInit {
		return layers.BFDState(s).String()
	}
	return fmt.Sprintf("Unknown (%d)", uint8(s))
}

// event describes a BFD state machine transition.
type event int

// In BFD, State information received from the remote is used as
// transitions in the local state machine. To be able to use the
// State as an Event, the integer values of States and Events
// need to be consistent.
const (
	eventAdminDown = event(layers.BFDStateAdminDown)
	eventDown      = event(layers.BFDStateDown)
	eventInit      = event(layers.BFDStateInit)
	eventUp        = event(layers.BFDStateUp)
	eventTimer     = event(4)
	eventAdminUp   = event(5)
)

func (e event) String() string {
	switch e {
	case eventAdminDown:
		return "Admin down"
	case eventDown:
		return "Down"
	case eventInit:
		return "Init"
	case eventUp:
		return "Up"
	case eventTimer:
		return "Timer"
	case eventAdminUp:
		return "Admin up"
	default:
		return fmt.Sprintf("Unknown (%d)", int(e))
	}
}

// transition implements the state machine for BFD.
//
// If the state or event is not defined by the state machine, the function panics.
func transition(currState state, e event) state {
	switch currState {
	case stateAdminDown:
		switch e {
		case eventAdminUp:
			return stateDown
		case eventInit, eventUp, eventDown, eventTimer, eventAdminDown:
			return stateAdminDown
		default:
			panic(fmt.Sprintf("unknown event: %v", e))
		}
	case stateDown:
		switch e {
		case eventInit:
			return stateUp
		case eventDown:
			return stateInit
		case eventUp, eventTimer, eventAdminUp:
			return stateDown
		case eventAdminDown:
			return stateAdminDown
		default:
			panic(fmt.Sprintf("unknown event: %v", e))
		}
	case stateInit:
		switch e {
		case eventInit, eventUp:
			return stateUp
		case eventTimer:
			return stateDown
		case eventDown, eventAdminUp:
			return stateInit
		case eventAdminDown:
			return stateAdminDown
		default:
			panic(fmt.Sprintf("unknown event: %v", e))
		}
	case stateUp:
		switch e {
		case eventInit, eventUp, eventAdminUp:
			return stateUp
		case eventTimer, eventDown:
			return stateDown
		case eventAdminDown:
			return stateAdminDown
		default:
			panic(fmt.Sprintf("unknown event: %v", e))
		}
	default:
		panic(fmt.Sprintf("unknown state: %v", currState))
	}
}
