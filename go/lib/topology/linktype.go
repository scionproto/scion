// Copyright 2017 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package topology

import (
	"strings"

	"github.com/scionproto/scion/go/lib/serrors"
)

// LinkType describes inter-AS links.
type LinkType int

// XXX(scrye): These constants might end up in files or on the network, so they should not
// change. They are defined here s.t. they are not subject to the protobuf generator.

const (
	// Unset is used for unknown link types.
	Unset LinkType = 0
	// Core links connect core ASes.
	Core LinkType = 1
	// Parent links are configured on non-core links pointing towards the core of an ISD.
	Parent LinkType = 2
	// Child links are configured on non-core links pointing away from the core of an ISD.
	Child LinkType = 3
	// Peer links are configured for peering relationships.
	Peer LinkType = 4
)

func (l LinkType) String() string {
	if l == Unset {
		return "unset"
	}
	s, err := l.MarshalText()
	if err != nil {
		return err.Error()
	}
	return string(s)
}

// LinkTypeFromString returns the numerical link type associated with a string description. If the
// string is not recognized, an Unset link type is returned. The matching is case-insensitive.
func LinkTypeFromString(s string) LinkType {
	var l LinkType
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return Unset
	}
	return l
}

func (l LinkType) MarshalText() ([]byte, error) {
	switch l {
	case Core:
		return []byte("core"), nil
	case Parent:
		return []byte("parent"), nil
	case Child:
		return []byte("child"), nil
	case Peer:
		return []byte("peer"), nil
	default:
		return nil, serrors.New("invalid link type")
	}
}

func (l *LinkType) UnmarshalText(data []byte) error {
	switch strings.ToLower(string(data)) {
	case "core":
		*l = Core
	case "parent":
		*l = Parent
	case "child":
		*l = Child
	case "peer":
		*l = Peer
	default:
		return serrors.New("invalid link type", "linkType", string(data))
	}
	return nil
}
