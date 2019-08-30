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
	"golang.org/x/xerrors"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/prom"
)

// ErrToMetricLabel classifies the error into a label that can be used in metrics.
func ErrToMetricLabel(err error) string {
	switch {
	case err == nil:
		return prom.Success
	case common.IsTimeoutErr(err):
		return prom.ErrTimeout
	case xerrors.Is(err, ErrInvalidInputData):
		return "input_data_invalid"
	case xerrors.Is(err, ErrDataInvalid):
		return "db_data_invalid"
	case xerrors.Is(err, ErrReadFailed):
		return "db_read"
	case xerrors.Is(err, ErrWriteFailed):
		return "db_write"
	case xerrors.Is(err, ErrTx):
		return "db_transaction"
	default:
		return err.Error()
	}
}
