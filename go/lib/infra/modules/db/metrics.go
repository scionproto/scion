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
	"errors"

	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/serrors"
)

// ErrToMetricLabel classifies the error into a label that can be used in metrics.
func ErrToMetricLabel(err error) string {
	switch {
	case err == nil:
		return prom.Success
	case serrors.IsTimeout(err):
		return prom.ErrTimeout
	case errors.Is(err, ErrInvalidInputData):
		return "err_input_data_invalid"
	case errors.Is(err, ErrDataInvalid):
		return "err_db_data_invalid"
	case errors.Is(err, ErrReadFailed):
		return "err_db_read"
	case errors.Is(err, ErrWriteFailed):
		return "err_db_write"
	case errors.Is(err, ErrTx):
		return "err_db_transaction"
	default:
		return prom.ErrNotClassified
	}
}
