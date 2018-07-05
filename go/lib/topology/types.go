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
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

const (
	CoreLinkName   = "CORE"
	ParentLinkName = "PARENT"
	ChildLinkName  = "CHILD"
	PeerLinkName   = "PEER"
)

func LinkTypeFromString(s string) (proto.LinkType, error) {
	linkType := proto.LinkTypeFromString(strings.ToLower(s))
	if linkType == 0 || linkType == proto.LinkType_unset {
		return proto.LinkType_unset, common.NewBasicError("Unknown link type", nil, "type", s)
	}
	return linkType, nil
}
