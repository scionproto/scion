// Copyright 2020 Anapaya Systems
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

package app_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/pkg/app"
)

func TestCodeError(t *testing.T) {
	base := fmt.Errorf("wrapped")
	err := app.WithExitCode(base, 42)
	assert.Equal(t, base.Error(), err.Error())
	assert.Equal(t, 42, app.ExitCode(err))
}

func TestExitCode(t *testing.T) {
	testCases := map[string]struct {
		Err  error
		Code int
	}{
		"nil": {
			Code: 0,
		},
		"with code": {
			Err:  app.WithExitCode(nil, 42),
			Code: 42,
		},
		"without code": {
			Err:  fmt.Errorf("some error"),
			Code: -1,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.Code, app.ExitCode(tc.Err))
		})
	}

}
