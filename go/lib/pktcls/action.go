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
	"github.com/netsec-ethz/scion/go/lib/pathmgr"
)

// Interface Action defines how paths and packets may be processed in a way
// that can be exported to JSON. Types implementing Action must not be
// marshaled to JSON directly; instead, first create an ActionMap, add the
// desired actions to it and then marshal the entire ActionMap.
type Action interface {
	Act(interface{}) interface{}
	GetName() string
	setName(s string)
	Typer
}

var _ Action = (*ActionFilterPaths)(nil)

// Filter only paths which match the embedded PathPredicate.
type ActionFilterPaths struct {
	Contains *pathmgr.PathPredicate
	Name     string `json:"-"`
}

func NewActionFilterPaths(name string, pp *pathmgr.PathPredicate) *ActionFilterPaths {
	return &ActionFilterPaths{Name: name, Contains: pp}
}

// Act takes an AppPathSet and returns a new AppPathSet containing only the
// paths permitted by the filter.
func (a *ActionFilterPaths) Act(aps interface{}) interface{} {
	return nil
}

func (a *ActionFilterPaths) GetName() string {
	return a.Name
}

func (a *ActionFilterPaths) setName(name string) {
	a.Name = name
}

func (a *ActionFilterPaths) Type() string {
	return TypeActionFilterPaths
}
