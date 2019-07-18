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
	InputDataErrMsg = "db: input data invalid"
	DataErrMsg      = "db: db data invalid"
	ReadErrMsg      = "db: read failed"
	WriteErrMsg     = "db: write failed"
	TxErrMsg        = "db: transaction error"
)

func NewTxError(msg string, err error, logCtx ...interface{}) error {
	return common.NewBasicError(TxErrMsg, err,
		append([]interface{}{"detailMsg", msg}, logCtx...)...)
}

func NewInputDataError(msg string, err error, logCtx ...interface{}) error {
	return common.NewBasicError(InputDataErrMsg, err,
		append([]interface{}{"detailMsg", msg}, logCtx...)...)
}

func NewDataError(msg string, err error, logCtx ...interface{}) error {
	return common.NewBasicError(DataErrMsg, err,
		append([]interface{}{"detailMsg", msg}, logCtx...)...)
}

func NewReadError(msg string, err error, logCtx ...interface{}) error {
	return common.NewBasicError(ReadErrMsg, err,
		append([]interface{}{"detailMsg", msg}, logCtx...)...)
}

func NewWriteError(msg string, err error, logCtx ...interface{}) error {
	return common.NewBasicError(WriteErrMsg, err,
		append([]interface{}{"detailMsg", msg}, logCtx...)...)
}
