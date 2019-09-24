// Copyright 2019 Anapaya Systems
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

package trust

import (
	"net"
)

// Recurser decides whether a recursive request is permitted for a given peer.
// For infra services use either ASLocalRecurser or LocalOnlyRecurser.
type Recurser interface {
	// AllowRecursion indicates whether the recursion is allowed for the
	// provided Peer. Recursions started by the local trust store have a nil
	// address and should generally be allowed.
	AllowRecursion(peer net.Addr) error
}

// ASLocalRecurser allows AS local addresses to start recursive requests.
type ASLocalRecurser struct {
	// TODO(roosd): implement
}

// LocalOnlyRecurser only allows requests from the application to recurse.
type LocalOnlyRecurser struct {
	// TODO(roosd): implement
}
