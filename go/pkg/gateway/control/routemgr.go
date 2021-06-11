// Copyright 2021 Anapaya Systems
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

package control

import (
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
)

// Diagnostics is the diagnostic information about the RouteDB.
type Diagnostics struct {
	Routes []Route
}

type Route struct {
	// Prefix is the IP address prefix of the route.
	Prefix *net.IPNet
	// NextHop is the next hop to send the packets to.
	NextHop net.IP
	// Source is the (optional) source hint for the IP route.
	Source net.IP
	// IA is the ISD-AS which contains the route prefix. For route prefixes not advertised
	// over SCION this is the Zero AS.
	IA addr.IA
}

func (r *Route) String() string {
	if r == nil {
		return "<nil>"
	}

	prefix := "<nil>"
	if r.Prefix != nil {
		prefix = r.Prefix.String()
	}

	nextHop := "<nil>"
	if r.NextHop != nil {
		nextHop = r.NextHop.String()
	}

	src := ""
	if r.Source != nil {
		// add a space for separation from previous word in final route
		src = " src " + r.Source.String()
	}

	ia := ""
	if !r.IA.IsZero() {
		ia = " isd-as " + r.IA.String()
	}
	return fmt.Sprintf("%s via %s%s%s", prefix, nextHop, src, ia)
}

// RouteUpdate is used to inform consumers about changes in the route database.
type RouteUpdate struct {
	Route
	// IsAdd is true if the route is added. It is false when the route is removed.
	IsAdd bool
}

// Publisher is the interface for announcing prefixes to other routing backends.
type Publisher interface {
	// AddRoute will export route to another routing backend. Duplicates are a no-op.
	AddRoute(route Route)
	// DeleteRoute will delete a route from another routing backend. If the route
	// doesn't exist, the deletion is a silent no-op. Only a network that is an exact
	// match (network address, subnet mask, next hop) is removed.
	DeleteRoute(route Route)
	// Close retracts all the routes published via this publisher.
	Close()
}

type PublisherFactory interface {
	NewPublisher() Publisher
}

// Consumer receives prefix updates via a channel.
type Consumer interface {
	// Updates returns a channel that can be used to receive route updates.
	Updates() <-chan RouteUpdate
	// Close tells the consumer to stop receiving updates (and clean up
	// allocated resources, if any).
	Close()
}

type ConsumerFactory interface {
	NewConsumer() Consumer
}
