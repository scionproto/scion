// Copyright 2020 Anapaya Systems
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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
)

func TestTopologySAnycast(t *testing.T) {
	topo := topologyS{Topology: MustLoadTopo(t, "testdata/basic.json")}
	topo.Topology.CS = nil
	a, err := topo.Anycast(addr.SvcCS)
	assert.Error(t, err)
	assert.Nil(t, a)
}

func TestTopologySMulticast(t *testing.T) {
	topo := topologyS{Topology: MustLoadTopo(t, "testdata/basic.json")}
	topo.Topology.CS = nil
	a, err := topo.Multicast(addr.SvcCS)
	assert.Error(t, err)
	assert.Nil(t, a)
}
