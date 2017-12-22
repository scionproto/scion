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

// Package infra contains common definitions for the SCION infrastructure
// messaging layer.
package infra

import (
	"fmt"

	. "github.com/scionproto/scion/go/lib/common"
)

const (
	strCtxDoneError   = "context canceled"
	strClosedError    = "layer closed"
	strAdapterError   = "msg adapter error"
	strInternalError  = "internal error"
	strTransportError = "transport error"
)

type errMeta struct {
	timeout bool
}

func NewCtxDoneError(ctx ...interface{}) error {
	meta := &errMeta{
		timeout: true,
	}
	return NewCErrorData(strCtxDoneError, meta, ctx...)
}

func WrapAdapterError(err error, ctx ...interface{}) error {
	return WrapError(err, strAdapterError, ctx...)
}

func WrapTransportError(err error, ctx ...interface{}) error {
	return WrapError(err, strTransportError, ctx...)
}

func WrapInternalError(err error, ctx ...interface{}) error {
	return WrapError(err, strInternalError, ctx...)
}

func NewClosedError(ctx ...interface{}) error {
	return NewError(strClosedError, ctx)
}

func NewError(errStr string, ctx ...interface{}) error {
	return NewCError(errStr, ctx)
}

// Returns true if err was
func IsTimeout(err error) bool {
	cmnErr, ok := err.(*CError)
	if !ok {
		return false
	}
	meta, ok := cmnErr.Data.(*errMeta)
	if !ok {
		return false
	}
	return meta.timeout
}

// Mutates the state of err to contain additional context, while preserving the
// original metadata.
func WrapError(err error, desc string, ctx ...interface{}) error {
	cmnErr, ok := err.(*CError)
	if !ok {
		// Convert standard error to CError
		cmnErr = NewCError(err.Error()).(*CError)
	}
	cmnErr.Ctx = append(ctx, "err", fmt.Sprintf("{%v}", cmnErr))
	cmnErr.Desc = desc
	return err
}
