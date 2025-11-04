// Copyright 2025 ETH Zurich
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

package hummingbird_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
)

func TestFlyoverHopSerializeDecodeFlyover(t *testing.T) {
	expected := &hummingbird.FlyoverHopField{
		HopField: path.HopField{
			IngressRouterAlert: true,
			EgressRouterAlert:  true,
			ExpTime:            63,
			ConsIngress:        1,
			ConsEgress:         0,
			Mac:                [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
		Flyover:      true,
		ResID:        782,
		Bw:           23,
		ResStartTime: 233,
		Duration:     11,
	}
	buf := make([]byte, hummingbird.ExportedFlyoverLen)
	assert.NoError(t, expected.SerializeTo(buf))

	got := &hummingbird.FlyoverHopField{}
	assert.NoError(t, got.DecodeFromBytes(buf))
	assert.Equal(t, expected, got)
}

func TestFlyoverHopSerializeDecode(t *testing.T) {
	expected := &hummingbird.FlyoverHopField{
		HopField: path.HopField{
			IngressRouterAlert: true,
			EgressRouterAlert:  false,
			ExpTime:            63,
			ConsIngress:        1,
			ConsEgress:         0,
			Mac:                [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
		Flyover:      false,
		ResID:        0,
		Bw:           0,
		ResStartTime: 0,
		Duration:     0,
	}
	buf := make([]byte, hummingbird.ExportedFlyoverLen)
	assert.NoError(t, expected.SerializeTo(buf))

	got := &hummingbird.FlyoverHopField{}
	assert.NoError(t, got.DecodeFromBytes(buf))
	assert.Equal(t, expected, got)
}
