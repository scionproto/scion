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
)

// Interface Action defines how paths and packets may be processed in a way
// that can be exported to JSON. Types implementing Action must not be
// marshaled to JSON directly; instead, first create an ActionMap, add the
// desired actions to it and then marshal the entire ActionMap.
type Action interface {
	Act(interface{}) interface{}
	GetName() string
	SetName(name string)
	Typer
}

// ActionMap is a container for Actions, keyed by their unique name. ActionMap
// can be used to marshal Actions to JSON. Unmarshaling back to ActionMap is
// guaranteed to yield an object that is identical to the initial one.
type ActionMap map[string]Action

func (am ActionMap) MarshalJSON() ([]byte, error) {
	m := make(map[string]*json.RawMessage)
	for k, v := range am {
		b, err := marshalInterface(v)
		if err != nil {
			return nil, err
		}
		m[k] = (*json.RawMessage)(&b)
	}
	if len(m) == 0 {
		m = nil
	}
	return json.Marshal(m)
}

func (am *ActionMap) UnmarshalJSON(b []byte) error {
	var m map[string]*json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	*am = make(map[string]Action)
	for k, v := range m {
		action, err := unmarshalAction(*v)
		if err != nil {
			return err
		}
		action.SetName(k)
		(*am)[k] = action
	}
	if len(*am) == 0 {
		*am = nil
	}
	return nil
}
