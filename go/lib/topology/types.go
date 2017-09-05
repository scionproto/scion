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

package topology

import (
	"fmt"
	"strings"

	"github.com/netsec-ethz/scion/go/lib/common"
)

// AS link types
type LinkType int

const (
	InvalidLink LinkType = iota
	CoreLink
	ParentLink
	ChildLink
	PeerLink
)

const (
	CoreLinkName   = "CORE"
	ParentLinkName = "PARENT"
	ChildLinkName  = "CHILD"
	PeerLinkName   = "PEER"
)

func LinkTypeFromString(s string) (LinkType, error) {
	switch strings.ToUpper(s) {
	case CoreLinkName:
		return CoreLink, nil
	case ParentLinkName:
		return ParentLink, nil
	case ChildLinkName:
		return ChildLink, nil
	case PeerLinkName:
		return PeerLink, nil
	default:
		return InvalidLink, common.NewCError("Unknown link type", "type", s)
	}
}

func (l LinkType) String() string {
	switch l {
	case CoreLink:
		return CoreLinkName
	case ParentLink:
		return ParentLinkName
	case ChildLink:
		return ChildLinkName
	case PeerLink:
		return PeerLinkName
	default:
		return fmt.Sprintf("Link type %+v unknown", int(l))
	}
}
