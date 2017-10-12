// Copyright 2017 ETH Zurich
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

package pktcls

import (
	"encoding/json"

	"github.com/netsec-ethz/scion/go/lib/common"
)

// ClassMap is a container for Classes, keyed by their unique name. Attempting
// to add a Class with the same name twice returns an error. ClassMap can be
// used to marshal Classes to JSON. Unmarshaling back to ClassMap is guaranteed
// to yield an object that is identical to the initial one.
type ClassMap struct {
	m map[string]*Class
}

func NewClassMap() *ClassMap {
	return &ClassMap{m: make(map[string]*Class)}
}

func (cm *ClassMap) Add(c *Class) error {
	_, ok := cm.m[c.name]
	if ok {
		return common.NewCError("Class name exists", "name", c.name)
	}
	cm.m[c.name] = c
	return nil
}

func (cm *ClassMap) Get(name string) (*Class, error) {
	class, ok := cm.m[name]
	if !ok {
		return nil, common.NewCError("Class not found", "name", name)
	}
	return class, nil
}

func (cm *ClassMap) Remove(name string) error {
	_, ok := cm.m[name]
	if !ok {
		return common.NewCError("Class not found", "name", name)
	}
	delete(cm.m, name)
	return nil
}

func (cm *ClassMap) MarshalJSON() ([]byte, error) {
	return json.MarshalIndent(cm.m, "", "    ")
}

func (cm *ClassMap) UnmarshalJSON(b []byte) error {
	err := json.Unmarshal(b, &cm.m)
	if err != nil {
		return err
	}
	for className, class := range cm.m {
		class.name = className
	}
	return nil
}
