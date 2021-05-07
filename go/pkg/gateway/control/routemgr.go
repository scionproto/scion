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

import "net"

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
