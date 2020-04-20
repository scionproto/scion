// Copyright 2016 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package util_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/lib/util"
)

// Interface assertions
var _ yaml.Marshaler = (*util.B64Bytes)(nil)
var _ yaml.Unmarshaler = (*util.B64Bytes)(nil)

func Test_B64B_String(t *testing.T) {
	b := util.B64Bytes{00, 01, 02, 03}
	assert.Equal(t, "00010203", b.String(), "String() should return hex-encoded string")
}

func Test_B64B_MarshalYAML(t *testing.T) {
	b := util.B64Bytes("hello, world")
	out, _ := yaml.Marshal(&b)
	assert.Equal(t, "aGVsbG8sIHdvcmxk\n", string(out),
		"Should marshal to a base64-encoded yaml entry")
}

func Test_B64B_UnmarshalYAML_YAMLParseError(t *testing.T) {
	var b util.B64Bytes
	err := yaml.Unmarshal([]byte("a: b"), &b)
	assert.Error(t, err, "YAML parse error")
	assert.Zero(t, b)
}

func Test_B64B_UnmarshalYAML_B64DecodeError(t *testing.T) {
	var b util.B64Bytes
	err := yaml.Unmarshal([]byte("_"), &b)
	assert.Error(t, err, "Base64 decode error")
	assert.Zero(t, b)
}

func Test_B64B_UnmarshalYAML_Success(t *testing.T) {
	var b util.B64Bytes
	err := yaml.Unmarshal([]byte("aGVsbG8sIHdvcmxk"), &b)
	if assert.NoError(t, err, "Valid sequence unmarshaled") {
		assert.Equal(t, util.B64Bytes("hello, world"), b)
	}
}
