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

package scmp

import (
	"fmt"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
)

var _ error = (*Error)(nil)
var _ common.ErrorNest = (*Error)(nil)

type Error struct {
	CT   ClassType
	Info Info
	Err  error
}

func NewError(class Class, type_ Type, info Info, e error) error {
	return &Error{CT: ClassType{class, type_}, Info: info, Err: e}
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	var s []string
	s = append(s, fmt.Sprintf("CT: %v", e.CT))
	if e.Info != nil {
		s = append(s, fmt.Sprintf("Info: %v", e.Info))
	}
	return strings.Join(s, " ")
}

func (e *Error) GetErr() error {
	return e.Err
}

func ToError(e error) *Error {
	if e, ok := e.(*Error); ok {
		return e
	}
	if n := common.GetNestedError(e); n != nil {
		return ToError(n)
	}
	return nil
}
