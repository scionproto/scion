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

package registration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmptyPortList(t *testing.T) {
	pl := newPortList()
	assert.Nil(t, pl.Get(), "Empty PortList should return nil on Get")
	assert.False(t, pl.Find(1))
	assert.Equal(t, 0, pl.Len())
	// Remove can't be tested on empty port list since we don't have a ring to remove.
}

func TestRemoval(t *testing.T) {
	pl := newPortList()
	r1 := pl.Insert(1, "1")
	pl.Remove(r1)
	require.Equal(t, pl.Len(), 0)

	r2 := pl.Insert(2, "2")
	require.Equal(t, "2", pl.Get())

	r1 = pl.Insert(1, "1")
	r3 := pl.Insert(3, "3")
	expectList(t, pl, "1", "2", "3")

	pl.Remove(r2)
	expectList(t, pl, "1", "3")
	r2 = pl.Insert(2, "2")

	pl.Remove(r1)
	expectList(t, pl, "2", "3")
	r1 = pl.Insert(1, "1")

	pl.Remove(r3)
	expectList(t, pl, "1", "2")
	pl.Remove(r2)
	expectList(t, pl, "1")
	pl.Remove(r1)
	expectList(t, pl)
}

func expectList(t *testing.T, pl *portList, expected ...string) {
	var actual []string
	for i := 0; i < pl.Len(); i++ {
		actual = append(actual, pl.Get().(string))
	}
	require.ElementsMatchf(t, actual, expected, "expected=%s actual=%s", expected, actual)
}
