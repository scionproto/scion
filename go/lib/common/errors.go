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
	"strings"

	"github.com/kormat/fmt15"
)

type ErrCtx fmt15.FCtx

type ErrorData interface{}

var _ error = (*CError)(nil)

type CError struct {
	Desc string
	Ctx  ErrCtx
	Data ErrorData
	Cerr *CError
}

func NewCError(desc string, ctx ...interface{}) error {
	return &CError{Desc: desc, Ctx: ctx}
}

func NewCErrorData(desc string, data ErrorData, ctx ...interface{}) error {
	return &CError{Desc: desc, Ctx: ctx, Data: data}
}

func (c CError) Error() string {
	// FIXME(kormat): handle nesting.
	s := []string{}
	s = append(s, c.Desc)
	for i := 0; i < len(c.Ctx); i += 2 {
		s = append(s, fmt.Sprintf("%s=\"%s\"", c.Ctx[i], c.Ctx[i+1]))
	}
	return strings.Join(s, " ")
}

func (c *CError) AddCtx(ctx ...interface{}) error {
	c.Ctx = append(c.Ctx, ctx...)
	return c
}

type Temporary interface {
	Temporary() bool
}

func IsTemporaryErr(e error) bool {
	t, ok := e.(Temporary)
	return ok && t.Temporary()
}
