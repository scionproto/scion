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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrFmt(t *testing.T) {
	f := func(t *testing.T, expect error, err error) {
		t.Helper()
		expectedMsg := fmt.Sprintf("%s {detailMsg=test}", expect)
		require.Equal(t, expectedMsg, err.Error())
	}

	f(t, ErrTx, NewTxError("test", nil))
	f(t, ErrInvalidInputData, NewInputDataError("test", nil))
	f(t, ErrDataInvalid, NewDataError("test", nil))
	f(t, ErrReadFailed, NewReadError("test", nil))
	f(t, ErrWriteFailed, NewWriteError("test", nil))
}
