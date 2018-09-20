// Copyright 2018 ETH Zurich
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

// Package itopo stores a singleton topology for reloading. Client packages
// that grab a reference with GetCurrentTopology are guaranteed to receive a
// stable snapshot of the topology.
//
// To change the pointer for future GetCurrentTopology calls, use
// SetCurrentTopology whenever topology information changes.
package itopo

import (
	"sync"

	"github.com/scionproto/scion/go/lib/topology"
)

var (
	topologyMtx     sync.RWMutex
	currentTopology *topology.Topo = nil
)

// SetCurrentTopology atomically sets the package-wide default topology to
// topo.
func SetCurrentTopology(topo *topology.Topo) {
	topologyMtx.Lock()
	currentTopology = topo
	topologyMtx.Unlock()
}

// GetCurrentTopology atomically returns a pointer to the package-wide
// default topology.
func GetCurrentTopology() *topology.Topo {
	topologyMtx.RLock()
	t := currentTopology
	topologyMtx.RUnlock()
	return t
}
