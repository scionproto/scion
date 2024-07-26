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

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/control/ifstate"
)

func TestInterfacesUpdate(t *testing.T) {
	t.Run("The update retains the state of the interface", func(t *testing.T) {
		intfs := testInterfaces(t)
		topoMap := map[uint16]ifstate.InterfaceInfo{
			1: {ID: 1, MTU: 1401},
			2: {ID: 2, MTU: 1402},
		}
		intfs.Update(topoMap)
		// The topo info should come from the updated map.
		assert.Equal(t, uint16(1401), intfs.Get(1).TopoInfo().MTU)
		assert.Equal(t, uint16(1402), intfs.Get(2).TopoInfo().MTU)
		// The remote ifID should be kept
		assert.EqualValues(t, 11, intfs.Get(1).TopoInfo().RemoteID)
		assert.EqualValues(t, 22, intfs.Get(2).TopoInfo().RemoteID)
	})
	t.Run("The update adds new interfaces and removes missing", func(t *testing.T) {
		intfs := testInterfaces(t)
		topoMap := map[uint16]ifstate.InterfaceInfo{
			3: {ID: 3, MTU: 1403},
		}
		intfs.Update(topoMap)
		assert.Nil(t, intfs.Get(1))
		assert.Nil(t, intfs.Get(2))
		assert.Equal(t, uint16(1403), intfs.Get(3).TopoInfo().MTU)
	})
}

func TestInterfacesReset(t *testing.T) {
	intfs := testInterfaces(t)
	intfs.Reset()
	// The topo info should remain.
	assert.Equal(t, uint16(1301), intfs.Get(1).TopoInfo().MTU)
	assert.Equal(t, uint16(1302), intfs.Get(2).TopoInfo().MTU)
	assert.EqualValues(t, 11, intfs.Get(1).TopoInfo().RemoteID)
	assert.EqualValues(t, 22, intfs.Get(2).TopoInfo().RemoteID)
}

func TestInterfacesAll(t *testing.T) {
	intfs := testInterfaces(t)
	all := intfs.All()
	assert.Equal(t, uint16(1301), all[1].TopoInfo().MTU)
	assert.Equal(t, uint16(1302), all[2].TopoInfo().MTU)
	assert.EqualValues(t, 11, all[1].TopoInfo().RemoteID)
	assert.EqualValues(t, 22, all[2].TopoInfo().RemoteID)
}

func testInterfaces(t *testing.T) *ifstate.Interfaces {
	topoMap := map[uint16]ifstate.InterfaceInfo{
		1: {ID: 1, MTU: 1301},
		2: {ID: 2, MTU: 1302},
	}
	intfs := ifstate.NewInterfaces(topoMap, ifstate.Config{})
	intfs.Get(1).TopoInfoRef().RemoteID = 11
	intfs.Get(2).TopoInfoRef().RemoteID = 22
	return intfs
}
