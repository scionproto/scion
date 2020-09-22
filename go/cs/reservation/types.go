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

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
)

// Capacities describes what a capacity description must offer.
type Capacities interface {
	IngressInterfaces() []common.IFIDType
	EgressInterfaces() []common.IFIDType
	Capacity(from, to common.IFIDType) uint64
	CapacityIngress(ingress common.IFIDType) uint64
	CapacityEgress(egress common.IFIDType) uint64
}

// MessageWithPath is used to send messages from the COLIBRI service via the BR.
type MessageWithPath interface {
	Path() *spath.Path
	// Payload() []byte
}
