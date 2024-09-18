// Copyright 2024 SCION Association
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

package iface_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/segment/iface"
)

func TestIfIDTypeUnmarshalJSON(t *testing.T) {
	t.Run("Simple Value", func(t *testing.T) {
		type exampleStruct struct {
			IfID iface.ID `json:"if_id"`
		}
		j := `{"if_id": 5}`
		var f exampleStruct
		require.NoError(t, json.Unmarshal([]byte(j), &f))
		assert.Equal(t, exampleStruct{IfID: 5}, f)
	})
	t.Run("Map keys", func(t *testing.T) {
		type exampleStruct struct {
			IfMap map[iface.ID]string `json:"if_map"`
		}
		j := `{"if_map": {"5": "foo"}}`
		var f exampleStruct
		require.NoError(t, json.Unmarshal([]byte(j), &f))
		assert.Equal(t, exampleStruct{IfMap: map[iface.ID]string{5: "foo"}}, f)
	})
}

func TestIfIDTypeUnmarshalText(t *testing.T) {
	var id iface.ID
	assert.NoError(t, id.UnmarshalText([]byte("1")))
	assert.Equal(t, iface.ID(1), id)
}
