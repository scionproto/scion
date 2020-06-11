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

package onehop_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/onehop"
)

func TestSerializeDecode(t *testing.T) {
	want := onehop.Path{
		Info: path.InfoField{
			ConsDir:   true,
			SegID:     0x222,
			Timestamp: 0x100,
		},
		FirstHop: path.HopField{
			IngressRouterAlert: true,
			EgressRouterAlert:  true,
			ExpTime:            63,
			ConsIngress:        0,
			ConsEgress:         1,
			Mac:                []byte{1, 2, 3, 4, 5, 6},
		},
		SecondHop: path.HopField{
			IngressRouterAlert: true,
			EgressRouterAlert:  true,
			ExpTime:            63,
			ConsIngress:        2,
			ConsEgress:         0,
			Mac:                []byte{1, 2, 3, 4, 5, 6},
		},
	}
	b := make([]byte, onehop.PathLen)
	assert.NoError(t, want.SerializeTo(b))

	got := onehop.Path{}
	assert.NoError(t, got.DecodeFromBytes(b))
	assert.Equal(t, want, got)
}
