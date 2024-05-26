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

package showpaths

import (
	"net"
)

// DefaultMaxPaths is the maximum number of paths that are displayed by default.
const DefaultMaxPaths = 10

// Config configures the showpath run.
type Config struct {
	// Local configures the local IP address to use. If this option is not provided,
	// a local IP that can reach SCION hosts is selected with the help of the kernel.
	Local net.IP
	// Daemon configures a specific SCION Daemon address.
	Daemon string
	// MaxPaths configures the maximum number of displayed paths. If this option is
	// not provided, the DefaultMaxPaths is used.
	MaxPaths int
	// Refresh configures whether the daemon is queried with the refresh flag.
	Refresh bool
	// NoProbe configures whether the path status is probed or not.
	NoProbe bool
	// Sequence is a string of space separated Hop Predicates that is used for
	// filtering.
	Sequence string
	// Epic filters paths for which EPIC is not available, and when probing, the
	// EPIC path type header is used.
	Epic bool
}
