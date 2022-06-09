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

import "github.com/scionproto/scion/pkg/log"

const (
	MinJitter            = minJitter
	MinJitterDetectMult1 = minJitterDetectMult1
	MaxJitter            = maxJitter

	StateInit      = stateInit
	StateDown      = stateDown
	StateUp        = stateUp
	StateAdminDown = stateAdminDown

	EventAdminDown = eventAdminDown
	EventDown      = eventDown
	EventInit      = eventInit
	EventUp        = eventUp
	EventTimer     = eventTimer
	EventAdminUp   = eventAdminUp
)

var (
	ShouldDiscard         = shouldDiscard
	DurationToBFDInterval = durationToBFDInterval
	BFDIntervalToDuration = bfdIntervalToDuration
	ComputeInterval       = computeInterval
	PrintPacket           = printPacket
	Transition            = transition
)

type (
	DefaultIntervalGenerator = defaultIntervalGenerator
	State                    = state
	Event                    = event
)

func (s *Session) SetLogger(logger log.Logger) {
	s.testLogger = logger
}
