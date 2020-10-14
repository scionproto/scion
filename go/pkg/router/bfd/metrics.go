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
	"github.com/scionproto/scion/go/lib/metrics"
)

// Metrics is used by sessions to report information about internal operation.
type Metrics struct {
	// PacketsSent reports the total number of BFD packets sent out by the session.
	PacketsSent metrics.Counter
	// PacketsReceived reports the total number of BFD packets received by the session.
	PacketsReceived metrics.Counter
	// Up reports 1 if the local session is in state Up, and 0 otherwise. Note that due to the
	// bidirectional detection nature of BFD (the local session will transition to a non-Up state if
	// it detects the remote is not Up), barring some network delays, if the local session is Up the
	// remote session is also Up.
	Up metrics.Gauge
	// StateChanges reports the total number of state changes of the session.
	StateChanges metrics.Counter
}
