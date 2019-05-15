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
)

func TestErrFmt(t *testing.T) {
	tests := []struct {
		Err      error
		Expected string
	}{
		{
			Err:      NewTxError("test", nil),
			Expected: fmt.Sprintf("%s detailMsg=\"test\"", TxErrMsg),
		},
		{
			Err:      NewInputDataError("test", nil),
			Expected: fmt.Sprintf("%s detailMsg=\"test\"", InputDataErrMsg),
		},
		{
			Err:      NewDataError("test", nil),
			Expected: fmt.Sprintf("%s detailMsg=\"test\"", DataErrMsg),
		},
		{
			Err:      NewReadError("test", nil),
			Expected: fmt.Sprintf("%s detailMsg=\"test\"", ReadErrMsg),
		},
		{
			Err:      NewWriteError("test", nil),
			Expected: fmt.Sprintf("%s detailMsg=\"test\"", WriteErrMsg),
		},
	}
	for _, test := range tests {
		checkStringEq(t, test.Err.Error(), test.Expected)
	}
}

func checkStringEq(t *testing.T, actual, expected string) {
	if actual != expected {
		t.Fatalf("Expected %s to be %s", actual, expected)
	}
}
