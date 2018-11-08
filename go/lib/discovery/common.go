// Copyright 2018 Anapaya Systems
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

package discovery

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/topology"
)

// InstancePool keeps a pool of known discovery service instances.
type InstancePool interface {
	// Update updates the pool based on a new discovery service map.
	Update(topology.IDAddrMap) error
	// Choose returns the info for the best discovery service instance
	// according to the pool.
	Choose() (InstanceInfo, error)
}

// InstanceInfo provides the information for a single discovery service instance.
type InstanceInfo interface {
	fmt.Stringer
	// Update updates the address.
	Update(*addr.AppAddr)
	// Key returns the key of the instance.
	Key() string
	// Addr returns the address of the instance.
	Addr() *addr.AppAddr
	// FailCount returns a number indicating how often
	// the instance has failed.
	FailCount() int
	// Fail adds to the fail count. This should be called by
	// the client when it fails to reach the instance.
	Fail()
}

// Fetcher is a periodic task that fetches topology form the discovery service.
type Fetcher interface {
	periodic.Task
	// UpdateInstances updates the discovery service instances for the fetcher.
	// It can be used to notify fetcher in case a new topology file has been
	// received from sources other than the discovery service
	// (e.g. through sighup reloading)
	UpdateInstances(topology.IDAddrMap) error
}
