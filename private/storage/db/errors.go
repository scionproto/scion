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
	"github.com/scionproto/scion/pkg/private/serrors"
)

var (
	// ErrInvalidInputData indicates invalid data was tried to input in the DB.
	ErrInvalidInputData = serrors.New("db: input data invalid")
	// ErrDataInvalid indicates invalid data is stored in the DB.
	ErrDataInvalid = serrors.New("db: db data invalid")
	// ErrReadFailed indicates that reading from the DB failed.
	ErrReadFailed = serrors.New("db: read failed")
	// ErrWriteFailed indicates that writing to the DB failed.
	ErrWriteFailed = serrors.New("db: write failed")
	// ErrTx indicates a transaction error.
	ErrTx = serrors.New("db: transaction error")
)

func NewTxError(msg string, err error, logCtx ...any) error {
	return serrors.JoinNoStack(ErrTx, err,
		append([]any{"detailMsg", msg}, logCtx...)...)
}

func NewInputDataError(msg string, err error, logCtx ...any) error {
	return serrors.JoinNoStack(ErrInvalidInputData, err,
		append([]any{"detailMsg", msg}, logCtx...)...)
}

func NewDataError(msg string, err error, logCtx ...any) error {
	return serrors.JoinNoStack(ErrDataInvalid, err,
		append([]any{"detailMsg", msg}, logCtx...)...)
}

func NewReadError(msg string, err error, logCtx ...any) error {
	return serrors.JoinNoStack(ErrReadFailed, err,
		append([]any{"detailMsg", msg}, logCtx...)...)
}

func NewWriteError(msg string, err error, logCtx ...any) error {
	return serrors.JoinNoStack(ErrWriteFailed, err,
		append([]any{"detailMsg", msg}, logCtx...)...)
}
