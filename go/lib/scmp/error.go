// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

	"github.com/scionproto/scion/go/lib/serrors"
)

// Error represents an SCMP error, with an optional nested error.
type Error struct {
	CT   ClassType
	Info Info
	Err  error
}

// NewError creates a new SCMP Error with the specified scmp Class/Type/Info,
// and optional nested error.
func NewError(class Class, t Type, info Info, e error) error {
	return &Error{CT: ClassType{class, t}, Info: info, Err: e}
}

func (e *Error) TopError() string {
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

func (e *Error) Error() string {
	return serrors.FmtError(e)
}

func (e *Error) Unwrap() error {
	return e.Err
}
