// Copyright 2019 ETH Zurich
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

package topology_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

func TestLinkType(t *testing.T) {
	// Protect LinkType from diverging from generated capnp data.
	assert.Equal(t, topology.Unset, topology.LinkType(proto.LinkType_unset))
	assert.Equal(t, topology.Core, topology.LinkType(proto.LinkType_core))
	assert.Equal(t, topology.Parent, topology.LinkType(proto.LinkType_parent))
	assert.Equal(t, topology.Child, topology.LinkType(proto.LinkType_child))
	assert.Equal(t, topology.Peer, topology.LinkType(proto.LinkType_peer))
}
