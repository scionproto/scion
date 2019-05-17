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
	"reflect"
	"sort"
	"testing"
)

func TestEmptyPortList(t *testing.T) {
	pl := newPortList()
	expectGet(t, pl, nil)
	expectFind(t, pl, 1, false)
	expectLen(t, pl, 0)
	// Remove can't be tested on empty port list since we don't have a ring to remove.
}

func TestRemoval(t *testing.T) {
	pl := newPortList()
	r1 := pl.Insert(1, "1")
	pl.Remove(r1)
	expectLen(t, pl, 0)
	r2 := pl.Insert(2, "2")
	expectGet(t, pl, "2")
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
}

func expectGet(t *testing.T, pl *portList, expected interface{}) {
	if v := pl.Get(); v != expected {
		t.Fatalf("Expected %s in Get but returned %s", expected, v)
	}
}

func expectList(t *testing.T, pl *portList, expected ...string) {
	var actual []string
	for i := 0; i < pl.Len(); i++ {
		actual = append(actual, pl.Get().(string))
	}
	sort.Slice(actual, func(i, j int) bool { return actual[i] < actual[j] })
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("Expected list to be %v but was %v", expected, actual)
	}
}

func expectLen(t *testing.T, pl *portList, expectedLen int) {
	if l := pl.Len(); l != expectedLen {
		t.Fatalf("List should have length %d but has %d", expectedLen, l)
	}
}

func expectFind(t *testing.T, pl *portList, val int, expectedFound bool) {
	if pl.Find(val) != expectedFound {
		if expectedFound {
			t.Fatalf("Expected %d to be found but wasn't", val)
		} else {
			t.Fatalf("Expected %d to not be found but was", val)
		}
	}
}
