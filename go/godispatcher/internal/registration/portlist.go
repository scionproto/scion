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

package registration

import (
	"container/ring"
)

// portList is a linked list of ports with a round-robin getter.
type portList struct {
	list *ring.Ring
}

func newPortList() *portList {
	return &portList{}
}

func (l *portList) Insert(port int, v interface{}) *ring.Ring {
	element := ring.New(1)
	element.Value = &listItem{port: port, value: v}
	if l.list == nil {
		l.list = element
	} else {
		l.list.Link(element)
	}
	return element
}

// Get returns an arbitrary object from the list.
//
// The objects are returned in round-robin fashion. Removing an element from
// the list can make the round-robin selection to reset from the start.
func (l *portList) Get() interface{} {
	v := l.list.Value
	l.list = l.list.Next()
	return v.(*listItem).value
}

func (l *portList) Find(port int) bool {
	var found bool
	l.list.Do(
		func(p interface{}) {
			if port == p.(*listItem).port {
				found = true
			}
		},
	)
	return found
}

func (l *portList) Remove(element *ring.Ring) {
	if element.Len() == 1 {
		l.list = nil
	} else {
		element.Prev().Unlink(1)
	}
}

func (l *portList) Len() int {
	return l.list.Len()
}

type listItem struct {
	port  int
	value interface{}
}
