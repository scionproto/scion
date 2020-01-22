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

package overlay_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/topology/overlay"
)

func TestTypeUnmarshalJSON(t *testing.T) {
	type exampleStruct struct {
		Type overlay.Type `json:"type"`
	}
	var e exampleStruct
	require.NoError(t, json.Unmarshal([]byte(`{"type": "UDP/IPv4"}`), &e))
	assert.Equal(t, exampleStruct{Type: overlay.UDPIPv4}, e)
}
