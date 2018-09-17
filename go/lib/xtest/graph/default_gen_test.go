// Copyright 2018 Anapaya Systems
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

package graph_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/lib/xtest/graph/gupdater"
)

func TestGeneratedUpToDate(t *testing.T) {
	Convey("GeneratedUpToDate", t, func() {
		g, err := gupdater.LoadGraph("../../../../topology/Default.topo")
		xtest.FailOnErr(t, err)
		actual := make(map[string]int, len(g.IfaceIds))
		for iface, id := range g.IfaceIds {
			actual[iface.Name()] = id
		}
		SoMsg("Ifaces same", graph.StaticIfaceIdMapping, ShouldResemble, actual)
	})
}
