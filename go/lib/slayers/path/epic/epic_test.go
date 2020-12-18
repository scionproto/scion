// Copyright 2020 ETH Zurich
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

package epic_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	libepic "github.com/scionproto/scion/go/lib/epic"
	"github.com/scionproto/scion/go/lib/slayers/path/epic"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
)

var (
	// Values for the SCION subheader are taken from scion_test.go and raw_test.go.
	rawScionPath = []byte(
		"\x00\x00\x20\x80\x00\x00\x01\x11\x00\x00\x01\x00\x01\x00\x02\x22\x00\x00" +
			"\x01\x00\x00\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06\x00\x3f\x00" +
			"\x03\x00\x02\x01\x02" +
			"\x03\x04\x05\x06\x00\x3f\x00\x00\x00\x02\x01\x02\x03\x04\x05\x06\x00" +
			"\x3f\x00\x01\x00\x00" +
			"\x01\x02\x03\x04\x05\x06")
	rawEpicPath = append([]byte("\x00\x00\x00\x01\x02\x00\x00\x03\x01\x02\x03\x04\x05\x06\x07\x08"),
		rawScionPath...)
	decodedScionPath = &scion.Raw{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrINF: 0,
				CurrHF:  0,
				SegLen:  [3]uint8{2, 2, 0},
			},
			NumINF:  2,
			NumHops: 4,
		},
		Raw: rawScionPath,
	}
)

func TestSerializeDecode(t *testing.T) {
	ts := libepic.CreateEpicTimestamp(1, 2, 3)
	want := epic.EpicPath{
		PacketTimestamp: ts,
		PHVF:            []byte{1, 2, 3, 4},
		LHVF:            []byte{5, 6, 7, 8},
		ScionRaw:        decodedScionPath,
	}

	b := make([]byte, want.Len())
	assert.NoError(t, want.SerializeTo(b))
	assert.Equal(t, rawEpicPath, b)

	got := epic.EpicPath{}
	assert.NoError(t, got.DecodeFromBytes(b))
	assert.Equal(t, want, got)
}
