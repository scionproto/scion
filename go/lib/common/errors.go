// Copyright 2016 ETH Zurich
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

package common

import (
	"fmt"

	"github.com/kormat/fmt15"
)

type Error struct {
	Desc string
	Ctx  fmt15.FCtx
	Data ErrorData
}

type ErrorData interface {
	fmt.Stringer
}

func NewError(desc string, ctx ...interface{}) *Error {
	e := &Error{Desc: desc}
	e.Ctx = make(fmt15.FCtx, 0, len(ctx)+2)
	e.Ctx = append(e.Ctx, fmt15.FCtx{"desc", desc}...)
	e.Ctx = append(e.Ctx, ctx...)
	return e
}

func NewErrorData(desc string, data ErrorData, ctx ...interface{}) *Error {
	e := NewError(desc, ctx...)
	e.Data = data
	return e
}

func (e Error) String() string {
	return fmt.Sprintf("%+v", e.Ctx)
}

func (e Error) Error() string {
	return e.String()
}
