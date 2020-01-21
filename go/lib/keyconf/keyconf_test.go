// Copyright 2018 ETH Zurich, Anapaya Systems
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

package keyconf

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	mstr0, _ = base64.StdEncoding.DecodeString("rJMIe7UcHTQxm9l13TuI3A==")
	mstr1, _ = base64.StdEncoding.DecodeString("WIn/OaISXyOCLehKNHcMKg==")
)

func TestLoadMaster(t *testing.T) {
	m, err := LoadMaster("testdata")
	require.NoError(t, err)
	assert.Equal(t, mstr0, m.Key0)
	assert.Equal(t, mstr1, m.Key1)
}
