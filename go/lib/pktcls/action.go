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
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/sciond"
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

var _ Action = (*ActionFilterPaths)(nil)

// ActionFilterPaths filters paths according to the embedded Cond object.
// CondAnyOf, CondAllOf, CondNot and CondPathPredicate conditions can be
// combined to implement complex path selection policies.
type ActionFilterPaths struct {
	Cond Cond
	Name string `json:"-"`
}

func NewActionFilterPaths(name string, cond Cond) *ActionFilterPaths {
	return &ActionFilterPaths{
		Name: name,
		Cond: cond,
	}
}

// Act takes an AppPathSet and returns a new AppPathSet containing only the
// paths permitted by the conditional predicate.
func (a *ActionFilterPaths) Act(values interface{}) interface{} {
	inputSet := values.(pathmgr.AppPathSet)
	resultSet := make(pathmgr.AppPathSet)
	for key, path := range inputSet {
		if a.Cond.Eval(path.Entry) {
			resultSet[key] = path
		}
	}
	return resultSet
}

func (a *ActionFilterPaths) GetName() string {
	return a.Name
}

func (a *ActionFilterPaths) SetName(name string) {
	a.Name = name
}

func (a *ActionFilterPaths) Type() string {
	return TypeActionFilterPaths
}

func (a *ActionFilterPaths) MarshalJSON() ([]byte, error) {
	return marshalInterface(a.Cond)
}

func (a *ActionFilterPaths) UnmarshalJSON(b []byte) error {
	var err error
	a.Cond, err = unmarshalCond(b)
	return err
}

var _ Cond = (*CondPathPredicate)(nil)

// CondPathPredicate implements interface Cond, and is designed for use in
// conditions for ActionFilterPaths. CondPathPredicate returns true if the
// argument to eval is a *sciond.PathReplyEntry that satisfies the embedded
// predicate PP.
type CondPathPredicate struct {
	PP *pathmgr.PathPredicate
}

func NewCondPathPredicate(pp *pathmgr.PathPredicate) *CondPathPredicate {
	return &CondPathPredicate{
		PP: pp,
	}
}

func (c *CondPathPredicate) Eval(v interface{}) bool {
	path := v.(*sciond.PathReplyEntry)
	return c.PP.Eval(path)
}

func (c *CondPathPredicate) Type() string {
	return TypeCondPathPredicate
}
