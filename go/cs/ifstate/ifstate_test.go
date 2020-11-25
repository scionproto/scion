// Copyright 2019 Anapaya Systems
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

package ifstate_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/topology"
)

func TestInterfacesUpdate(t *testing.T) {
	t.Run("The update retains the state of the interface", func(t *testing.T) {
		intfs := testInterfaces(t)
		topoMap := topology.IfInfoMap{
			1: {BRName: "BR-1-new"},
			2: {BRName: "BR-2-new"},
		}
		intfs.Update(topoMap)
		// The topo info should come from the updated map.
		assert.Equal(t, "BR-1-new", intfs.Get(1).TopoInfo().BRName)
		assert.Equal(t, "BR-2-new", intfs.Get(2).TopoInfo().BRName)
		// The remote ifid should be kept
		assert.EqualValues(t, 11, intfs.Get(1).TopoInfo().RemoteIFID)
		assert.EqualValues(t, 22, intfs.Get(2).TopoInfo().RemoteIFID)
	})
	t.Run("The update adds new interfaces and removes missing", func(t *testing.T) {
		intfs := testInterfaces(t)
		topoMap := topology.IfInfoMap{
			3: {BRName: "BR-3-new"},
		}
		intfs.Update(topoMap)
		assert.Nil(t, intfs.Get(1))
		assert.Nil(t, intfs.Get(2))
		assert.Equal(t, "BR-3-new", intfs.Get(3).TopoInfo().BRName)
	})
}

func TestInterfacesReset(t *testing.T) {
	intfs := testInterfaces(t)
	intfs.Reset()
	// The topo info should remain.
	assert.Equal(t, "BR-1", intfs.Get(1).TopoInfo().BRName)
	assert.Equal(t, "BR-1", intfs.Get(1).TopoInfo().BRName)
	assert.Equal(t, "BR-2", intfs.Get(2).TopoInfo().BRName)
	assert.EqualValues(t, 11, intfs.Get(1).TopoInfo().RemoteIFID)
	assert.EqualValues(t, 22, intfs.Get(2).TopoInfo().RemoteIFID)
}

func TestInterfacesAll(t *testing.T) {
	Convey("Given an interface infos map with existing entries", t, func() {
		intfs := testInterfaces(t)
		Convey("All should return all infos", func() {
			all := intfs.All()
			// The topo info should remain.
			SoMsg("Name 1", all[1].TopoInfo().BRName, ShouldEqual, "BR-1")
			SoMsg("Name 2", all[2].TopoInfo().BRName, ShouldEqual, "BR-2")
			SoMsg("Ifid 1", all[1].TopoInfo().RemoteIFID, ShouldEqual, 11)
			SoMsg("Ifid 2", all[2].TopoInfo().RemoteIFID, ShouldEqual, 22)
		})
	})
}

func testInterfaces(t *testing.T) *ifstate.Interfaces {
	topoMap := topology.IfInfoMap{
		1: {BRName: "BR-1"},
		2: {BRName: "BR-2"},
	}
	intfs := ifstate.NewInterfaces(topoMap, ifstate.Config{})
	intfs.Get(1).TopoInfoRef().RemoteIFID = 11
	intfs.Get(2).TopoInfoRef().RemoteIFID = 22
	return intfs
}
