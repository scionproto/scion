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

package infra_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
)

func TestResponseWriterFromContext(t *testing.T) {
	tests := map[string]struct {
		Ctx        context.Context
		ExpectedRW infra.ResponseWriter
		ExpectedOK bool
	}{
		"nil context": {
			Ctx:        nil,
			ExpectedRW: nil,
			ExpectedOK: false,
		},
		"key not found": {
			Ctx:        context.Background(),
			ExpectedRW: nil,
			ExpectedOK: false,
		},
		"value is nil": {
			Ctx:        infra.NewContextWithResponseWriter(context.Background(), nil),
			ExpectedRW: nil,
			ExpectedOK: false,
		},
		"valid": {
			Ctx: infra.NewContextWithResponseWriter(context.Background(),
				&mock_infra.MockResponseWriter{}),
			ExpectedRW: &mock_infra.MockResponseWriter{},
			ExpectedOK: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			rw, ok := infra.ResponseWriterFromContext(test.Ctx)
			assert.Equal(t, test.ExpectedRW, rw)
			assert.Equal(t, test.ExpectedOK, ok)
		})
	}
}
