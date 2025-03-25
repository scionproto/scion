// Copyright 2017 ETH Zurich
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

/*
Package proto used to contain mostly auto-generated code for parsing/packing
SCION capnproto protocol structs. This has all been replaced by gRPC/protobuf
or otherwise replaced. Only a few left-over enums are still in use and were
extracted from the auto-generated code.  These should be moved to a more
suitable place eventually.
*/
package proto

import "fmt"

type LinkType uint16

// Values of LinkType.
const (
	LinkType_unset  LinkType = 0
	LinkType_core   LinkType = 1
	LinkType_parent LinkType = 2
	LinkType_child  LinkType = 3
	LinkType_peer   LinkType = 4
)

// String returns the enum's constant name.
func (c LinkType) String() string {
	switch c {
	case LinkType_unset:
		return "unset"
	case LinkType_core:
		return "core"
	case LinkType_parent:
		return "parent"
	case LinkType_child:
		return "child"
	case LinkType_peer:
		return "peer"

	default:
		return ""
	}
}

// LinkTypeFromString returns the enum value with a name,
// or the zero value if there's no such value.
func LinkTypeFromString(c string) LinkType {
	switch c {
	case "unset":
		return LinkType_unset
	case "core":
		return LinkType_core
	case "parent":
		return LinkType_parent
	case "child":
		return LinkType_child
	case "peer":
		return LinkType_peer

	default:
		return 0
	}
}

type PathSegType uint16

// Values of PathSegType.
const (
	PathSegType_unset PathSegType = 0
	PathSegType_up    PathSegType = 1
	PathSegType_down  PathSegType = 2
	PathSegType_core  PathSegType = 3
)

// String returns the enum's constant name.
func (c PathSegType) String() string {
	switch c {
	case PathSegType_unset:
		return "unset"
	case PathSegType_up:
		return "up"
	case PathSegType_down:
		return "down"
	case PathSegType_core:
		return "core"
	default:
		return fmt.Sprintf("unknown(%d)", c)
	}
}

// PathSegTypeFromString returns the enum value with a name,
// or the zero value if there's no such value.
func PathSegTypeFromString(c string) PathSegType {
	switch c {
	case "unset":
		return PathSegType_unset
	case "up":
		return PathSegType_up
	case "down":
		return PathSegType_down
	case "core":
		return PathSegType_core

	default:
		return 0
	}
}
