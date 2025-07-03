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

package common_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/private/common"
)

func TestTypeOf(t *testing.T) {
	type A struct{}
	tests := map[string]any{
		"nil":       nil,
		"typed nil": (*A)(nil),
		"ptr":       &A{},
		"struct":    A{},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var result string
			assert.NotPanics(t, func() { result = common.TypeOf(test) })
			assert.NotEmpty(t, result)
		})
	}
}
