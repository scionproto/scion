// Copyright 2019 Anapaya Systems
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

package db

import (
	"github.com/scionproto/scion/go/lib/common"
)

const (
	// ErrInvalidInputData indicates invalid data was tried to input in the DB.
	ErrInvalidInputData common.ErrMsg = "db: input data invalid"
	// ErrDataInvalid indicates invalid data is stored in the DB.
	ErrDataInvalid common.ErrMsg = "db: db data invalid"
	// ErrReadFailed indicates that reading from the DB failed.
	ErrReadFailed common.ErrMsg = "db: read failed"
	// ErrWriteFailed indicates that writing to the DB failed.
	ErrWriteFailed common.ErrMsg = "db: write failed"
	// ErrTx indicates a transaction error.
	ErrTx common.ErrMsg = "db: transaction error"
)

func NewTxError(msg string, err error, logCtx ...interface{}) error {
	return common.NewBasicError(ErrTx, err,
		append([]interface{}{"detailMsg", msg}, logCtx...)...)
}

func NewInputDataError(msg string, err error, logCtx ...interface{}) error {
	return common.NewBasicError(ErrInvalidInputData, err,
		append([]interface{}{"detailMsg", msg}, logCtx...)...)
}

func NewDataError(msg string, err error, logCtx ...interface{}) error {
	return common.NewBasicError(ErrDataInvalid, err,
		append([]interface{}{"detailMsg", msg}, logCtx...)...)
}

func NewReadError(msg string, err error, logCtx ...interface{}) error {
	return common.NewBasicError(ErrReadFailed, err,
		append([]interface{}{"detailMsg", msg}, logCtx...)...)
}

func NewWriteError(msg string, err error, logCtx ...interface{}) error {
	return common.NewBasicError(ErrWriteFailed, err,
		append([]interface{}{"detailMsg", msg}, logCtx...)...)
}
