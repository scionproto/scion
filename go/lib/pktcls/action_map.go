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

// ActionMap is a container for Actions, keyed by their unique name. Attempting
// to add an Action with the same name twice returns an error. ActionMap can be
// used to marshal Actions to JSON. Unmarshaling back to ActionMap is
// guaranteed to yield an object that is identical to the initial one.
type ActionMap map[string]Action

func NewActionMap() ActionMap {
	return make(ActionMap)
}

func (am ActionMap) Add(c Action) error {
	_, ok := am[c.GetName()]
	if ok {
		return common.NewCError("Action name exists", "name", c.GetName())
	}
	am[c.GetName()] = c
	return nil
}

func (am ActionMap) Get(name string) (Action, error) {
	class, ok := am[name]
	if !ok {
		return nil, common.NewCError("Action not found", "name", name)
	}
	return class, nil
}

func (am ActionMap) Remove(name string) error {
	_, ok := am[name]
	if !ok {
		return common.NewCError("Action not found", "name", name)
	}
	delete(am, name)
	return nil
}

func (am ActionMap) MarshalJSON() ([]byte, error) {
	m := make(map[string]*json.RawMessage)
	for k, v := range am {
		b, err := marshalInterface(v)
		if err != nil {
			return nil, err
		}
		m[k] = (*json.RawMessage)(&b)
	}
	return json.Marshal(m)
}

func (am *ActionMap) UnmarshalJSON(b []byte) error {
	m := make(map[string]*json.RawMessage)
	err := json.Unmarshal(b, &m)
	if err != nil {
		return err
	}

	*am = make(map[string]Action)
	for k, v := range m {
		action, err := unmarshalAction(*v)
		if err != nil {
			return err
		}
		action.setName(k)
		(*am)[k] = action
	}
	return nil
}
