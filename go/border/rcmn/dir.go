// Copyright 2016 ETH Zurich
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

// Package rcmn contains small common types used by the border router, to
// eliminate circular dependencies.
package rcmn

// Dir represents a packet direction. It is used to designate where a packet
// came from, and where it is going to.
type Dir int

const (
	// DirUnset is the zero-value for Dir, and means the direction hasn't been initialized.
	DirUnset Dir = iota
	// DirSelf means the packet is going to/coming from this router.
	DirSelf
	// DirLocal means the packet is going to/coming from the local ISD-AS.
	DirLocal
	// DirExternal means the packet is going to/coming from another ISD-AS.
	DirExternal
)

func (d Dir) String() string {
	switch d {
	case DirUnset:
		return "Unset"
	case DirSelf:
		return "Self"
	case DirLocal:
		return "Local"
	case DirExternal:
		return "External"
	default:
		return "UNKNOWN"
	}
}
