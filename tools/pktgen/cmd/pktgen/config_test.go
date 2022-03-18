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

package main_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	main "github.com/scionproto/scion/tools/pktgen/cmd/pktgen"
)

func TestParseSample(t *testing.T) {
	raw, err := os.ReadFile("testdata/sample.json")
	require.NoError(t, err)
	var cfg main.JSONConfig
	err = json.Unmarshal(raw, &cfg)
	assert.NoError(t, err)
}
