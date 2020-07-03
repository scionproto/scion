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
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
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

func TestPathToSCIONDecoded(t *testing.T) {
	t.Run("complete path converts correctly", func(t *testing.T) {
		t.Parallel()
		input := onehop.Path{
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
		want := &scion.Decoded{
			Base: scion.Base{
				PathMeta: scion.MetaHdr{
					CurrHF:  0,
					CurrINF: 0,
					SegLen:  [3]uint8{2, 0, 0},
				},
				NumHops: 2,
				NumINF:  1,
			},
			HopFields:  []*path.HopField{&input.FirstHop, &input.SecondHop},
			InfoFields: []*path.InfoField{&input.Info},
		}
		sp, err := input.ToSCIONDecoded()
		assert.NoError(t, err)
		assert.Equal(t, want, sp)
	})
	t.Run("incomplete path", func(t *testing.T) {
		t.Parallel()
		input := onehop.Path{
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
		}
		sp, err := input.ToSCIONDecoded()
		assert.Error(t, err)
		assert.Nil(t, sp)
	})
}
