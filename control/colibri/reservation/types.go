// Copyright 2020 ETH Zurich, Anapaya Systems
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

package reservation

// Capacities describes what a capacity description must offer.
type Capacities interface {
	IngressInterfaces() []uint16
	EgressInterfaces() []uint16
	Capacity(from, to uint16) uint64
	CapacityIngress(ingress uint16) uint64
	CapacityEgress(egress uint16) uint64
}

// ColibriPath is a path of type COLIBRI.
// This type will be moved to its right place in slayers once the header has been approved.
// TODO(juagargi): move the type to slayers.
type ColibriPath interface {
	Copy() ColibriPath
	// Reverse reverses the contained path.
	Reverse() error
	NumberOfHops() int
	IndexOfCurrentHop() int
	IngressEgressIFIDs() (uint16, uint16)
}

// MessageWithPath is used to send messages from the COLIBRI service via the BR.
type MessageWithPath interface {
	Path() ColibriPath
	// Payload() []byte
}
