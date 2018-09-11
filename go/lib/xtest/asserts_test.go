// Copyright 2018 ETH Zurich
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

package xtest

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestContainerEq(t *testing.T) {
	Convey("Two empty maps of same type are equal", t, func() {
		x := map[int]int{}
		y := map[int]int{}
		SoMsg("equals", ContainerEq(x, y), ShouldBeTrue)
	})
	Convey("An empty map does not equal a map with one element", t, func() {
		x := map[int]int{}
		y := map[int]int{5: 5}
		SoMsg("equals", ContainerEq(x, y), ShouldBeFalse)
	})
	Convey("Two one element maps are not equal if the values are not equal", t, func() {
		x := map[int]int{4: 4}
		y := map[int]int{5: 5}
		SoMsg("equals", ContainerEq(x, y), ShouldBeFalse)
	})
	Convey("Two maps with the same element should be equal", t, func() {
		x := map[int]int{5: 5}
		y := map[int]int{5: 5}
		SoMsg("equals", ContainerEq(x, y), ShouldBeTrue)
	})
	Convey("Second map contains extra values, so maps are not equal", t, func() {
		x := map[int]int{4: 4}
		y := map[int]int{4: 4, 5: 5}
		SoMsg("equals", ContainerEq(x, y), ShouldBeFalse)
	})
	Convey("An empty map and empty slice are equal", t, func() {
		x := map[int]int{}
		y := []int{}
		SoMsg("equals", ContainerEq(x, y), ShouldBeTrue)
	})
	Convey("Two permutations are equal", t, func() {
		x := []int{1, 2, 3, 4}
		y := []int{4, 1, 3, 2}
		SoMsg("equals", ContainerEq(x, y), ShouldBeTrue)
	})
}

func TestSubsetoOf(t *testing.T) {
	Convey("Empty map is a subset of an empty map", t, func() {
		So(ContainerIsSubsetOf(map[int]int{}, map[int]int{}), ShouldBeTrue)
	})
	Convey("Empty map is a subset of empty slice", t, func() {
		So(ContainerIsSubsetOf(map[int]int{}, []string{}), ShouldBeTrue)
	})
	Convey("Map with one value is not a subset of empty map", t, func() {
		So(ContainerIsSubsetOf(map[int]int{0: 5}, map[int]int{}), ShouldBeFalse)
	})
	Convey("Map with one value is not a subset of map with other values", t, func() {
		So(ContainerIsSubsetOf(map[int]int{0: 5}, map[int]int{4: 6, 5: 7}), ShouldBeFalse)
	})
	Convey("Map with one value is a subset of map with that value and others", t, func() {
		So(ContainerIsSubsetOf(map[int]int{0: 5}, map[int]int{1: 5, 2: 6}), ShouldBeTrue)
	})
	Convey("Slice with one value is not a subset of map with other values ", t, func() {
		So(ContainerIsSubsetOf([]int{5}, map[int]int{1: 6, 2: 7}), ShouldBeFalse)
	})
	Convey("Map with one value is a subset of slice with that value and others", t, func() {
		So(ContainerIsSubsetOf(map[int]int{0: 5}, []int{5, 6}), ShouldBeTrue)
	})
}

func TestValueInCollection(t *testing.T) {
	Convey("An object is not included in an empty map", t, func() {
		So(ValueIsContainedIn(5, map[int]int{}), ShouldBeFalse)
	})
	Convey("An object is not included in an empty slice", t, func() {
		So(ValueIsContainedIn(5, []int{}), ShouldBeFalse)
	})
	Convey("An object is included in a map containing the value", t, func() {
		So(ValueIsContainedIn(5, map[string]int{"x": 5}), ShouldBeTrue)
	})
	Convey("An object is not included in a map containing values", t, func() {
		So(ValueIsContainedIn(5, map[int]string{5: "x"}), ShouldBeFalse)
	})
	Convey("An object is included in a slice containing the value", t, func() {
		So(ValueIsContainedIn(5, []int{5}), ShouldBeTrue)
	})
	Convey("An object is not included in a slice containing values", t, func() {
		So(ValueIsContainedIn(5, []string{"foo"}), ShouldBeFalse)
	})
}

func TestCollectionLength(t *testing.T) {
	Convey("An empty map has length 0", t, func() {
		So(ContainerLength(map[int]int{}), ShouldEqual, 0)
	})
	Convey("A map with one element has length 1", t, func() {
		So(ContainerLength(map[string]string{"x": "x"}), ShouldEqual, 1)
	})
	Convey("An empty slice has length 0", t, func() {
		So(ContainerLength([]int{}), ShouldEqual, 0)
	})
	Convey("A slice with one element has length 1", t, func() {
		So(ContainerLength([]int{1}), ShouldEqual, 1)
	})
	Convey("Passing in an int causes a panic", t, func() {
		So(func() { ContainerLength(5) }, ShouldPanic)
	})
}
