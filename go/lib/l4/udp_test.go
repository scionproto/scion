// Copyright 2017 Audrius Meskauskas with all possible permissions granted
// to ETH Zurich and Anapaya Systems
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

package l4

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/common"
)

// Create UDP structure
func createUDP() UDP {
	// Use hex, easier seen in binary dump
	return UDP{0x1234, 0x5678, 0xA, make(common.RawBytes, 2)}
}

func TestUDPFromRaw(t *testing.T) {
	raw := common.RawBytes{0x12, 0x34, 0x56, 0x78, 0, 0xA, 0, 0}
	original := createUDP()

	fromRaw, err := UDPFromRaw(raw)
	assert.NoError(t, err)
	assert.Equal(t, &original, fromRaw)
}

func TestUDPValidate(t *testing.T) {
	u := createUDP()

	assert.Equal(t, uint16(10), u.TotalLen)
	err := u.Validate(int(u.TotalLen) - UDPLen)
	assert.NoError(t, err)
}

func TestUDPParse(t *testing.T) {
	// assuming we have tested UDPPack
	expected := createUDP()
	raw, err := expected.Pack(true)
	actual := UDP{0, 0, 0xA,
		make(common.RawBytes, 2)}

	actual.Parse(raw)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestUDPPack(t *testing.T) {
	u := createUDP()
	raw, err := u.Pack(true)

	assert.NoError(t, err)
	assert.Equal(t, common.RawBytes{0x12, 0x34, 0x56, 0x78, 0, 0xA, 0, 0}, raw)
}

func TestUDPWrite(t *testing.T) {
	u := createUDP()
	raw := make(common.RawBytes, 8)
	err := u.Write(raw)

	assert.NoError(t, err)
	assert.Equal(t, common.RawBytes{0x12, 0x34, 0x56, 0x78, 0, 0xA, 0, 0}, raw)
}
