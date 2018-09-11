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
	"reflect"
)

// ContainerEq returns true if the arguments contain the same unique values.
// This is defined as "every value in the first container is contained in the
// second container, and every value in the second container is contained in
// the first container". For example, ContainerEq on slices [5, 5] and [5] will
// return true, as 5 is present in both.
//
// For value comparison, reflect.DeepEqual is used.
//
// Arguments need to be of either type map or slice. For maps, the keys are ignored.
//
// The current implementation has poor complexity (O(n^2)) and should only be
// used in tests.
func ContainerEq(containerX, containerY interface{}) bool {
	return ContainerIsSubsetOf(containerX, containerY) &&
		ContainerIsSubsetOf(containerY, containerX)
}

func ContainerIsSubsetOf(containerX, containerY interface{}) bool {
	s := reflect.ValueOf(containerX)
	switch reflect.TypeOf(containerX).Kind() {
	case reflect.Map:
		keys := s.MapKeys()
		for i := 0; i < len(keys); i++ {
			if !ValueIsContainedIn(s.MapIndex(keys[i]).Interface(), containerY) {
				return false
			}
		}
	case reflect.Slice:
		for i := 0; i < ContainerLength(containerX); i++ {
			if !ValueIsContainedIn(s.Index(i).Interface(), containerY) {
				return false
			}
		}
	}
	return true
}

func ValueIsContainedIn(value, container interface{}) bool {
	s := reflect.ValueOf(container)
	switch reflect.TypeOf(container).Kind() {
	case reflect.Map:
		keys := s.MapKeys()
		for i := 0; i < len(keys); i++ {
			if reflect.DeepEqual(value, s.MapIndex(keys[i]).Interface()) {
				return true
			}
		}
	case reflect.Slice:
		for i := 0; i < ContainerLength(container); i++ {
			if reflect.DeepEqual(value, s.Index(i).Interface()) {
				return true
			}
		}
	}
	return false
}

func ContainerLength(m interface{}) int {
	switch reflect.TypeOf(m).Kind() {
	case reflect.Map:
		return reflect.ValueOf(m).Len()
	case reflect.Slice:
		return reflect.ValueOf(m).Len()
	default:
		panic("value is not collection")
	}
}
