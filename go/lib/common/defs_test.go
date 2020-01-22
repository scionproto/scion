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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/common"
)

func TestTypeOf(t *testing.T) {
	type A struct{}
	tests := map[string]interface{}{
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

func TestIFIDTypeUnmarshalJSON(t *testing.T) {
	t.Run("Simple Value", func(t *testing.T) {
		type exampleStruct struct {
			IfID common.IFIDType `json:"if_id"`
		}
		j := `{"if_id": 5}`
		var f exampleStruct
		require.NoError(t, json.Unmarshal([]byte(j), &f))
		assert.Equal(t, exampleStruct{IfID: 5}, f)
	})
	t.Run("Map keys", func(t *testing.T) {
		type exampleStruct struct {
			IfMap map[common.IFIDType]string `json:"if_map"`
		}
		j := `{"if_map": {"5": "foo"}}`
		var f exampleStruct
		require.NoError(t, json.Unmarshal([]byte(j), &f))
		assert.Equal(t, exampleStruct{IfMap: map[common.IFIDType]string{5: "foo"}}, f)
	})
}

func TestIFIDTypeUnmarshalText(t *testing.T) {
	var id common.IFIDType
	assert.NoError(t, id.UnmarshalText([]byte("1")))
	assert.Equal(t, common.IFIDType(1), id)
}
