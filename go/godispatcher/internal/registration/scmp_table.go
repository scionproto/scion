// Copyright 2019 ETH Zurich
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
	"github.com/scionproto/scion/go/lib/common"
)

// SCMPTable tracks SCMP General class IDs.
//
// Attempting to register the same ID more than once will return an error.
type SCMPTable struct {
	m map[uint64]interface{}
}

func NewSCMPTable() *SCMPTable {
	return &SCMPTable{m: make(map[uint64]interface{})}
}

func (t *SCMPTable) Lookup(id uint64) (interface{}, bool) {
	value, ok := t.m[id]
	return value, ok
}

func (t *SCMPTable) Register(id uint64, value interface{}) error {
	if value == nil {
		return common.NewBasicError("cannot register nil value", nil)
	}
	if _, ok := t.m[id]; ok {
		return common.NewBasicError("id already registered", nil, "id", id)
	}
	t.m[id] = value
	return nil
}

func (t *SCMPTable) Remove(id uint64) {
	delete(t.m, id)
}
