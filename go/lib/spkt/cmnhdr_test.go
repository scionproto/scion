// Copyright 2017 ETH Zurich
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

package spkt

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scmp"
)

var cmnhInput = [CmnHdrLen]byte{0x01, 0xf8, 0x0c, 0xb6, 0x1f, 0xab, 0xcd, 0xef}

func TestCmnHdrParse(t *testing.T) {
	t.Run("CmnHdr.Parse should parse bytes correctly", func(t *testing.T) {
		cmn := &CmnHdr{}
		assert.NoError(t, cmn.Parse(cmnhInput[:]))
		assert.EqualValues(t, 0x0, cmn.Ver)
		assert.EqualValues(t, 0x07, cmn.DstType)
		assert.EqualValues(t, 0x38, cmn.SrcType)
		assert.EqualValues(t, 0x0cb6, cmn.TotalLen)
		assert.EqualValues(t, 0x1f, cmn.HdrLen)
		assert.EqualValues(t, 0xab, cmn.CurrInfoF)
		assert.EqualValues(t, 0xcd, cmn.CurrHopF)
		assert.EqualValues(t, 0xef, cmn.NextHdr)
	})
	t.Run("CmnHdr.Parse should report unsupported version", func(t *testing.T) {
		cmn := &CmnHdr{}
		input := append([]byte(nil), cmnhInput[:]...)
		input[0] |= 0x30
		err := cmn.Parse(input)
		assert.Error(t, err)
		var serr *scmp.Error
		require.True(t, errors.As(err, &serr))
		assert.Error(t, serr)
		assert.Equal(t, scmp.ClassType{Class: scmp.C_CmnHdr, Type: scmp.T_C_BadVersion}, serr.CT)
		assert.EqualValues(t, 0x3, cmn.Ver)
	})
}

func TestCmnHdrWrite(t *testing.T) {
	cmn := &CmnHdr{
		Ver: 0x0, DstType: 0x07, SrcType: 0x38, TotalLen: 0x0cb6,
		HdrLen: 0x1f, CurrInfoF: 0xab, CurrHopF: 0xcd, NextHdr: 0xef,
	}
	out := make([]byte, CmnHdrLen)
	cmn.Write(out)
	assert.Equal(t, cmnhInput[:], out)
}

func TestCmnHdrUpdatePathOffsets(t *testing.T) {
	cmn := &CmnHdr{}
	cmn.Parse(cmnhInput[:])
	out := make([]byte, CmnHdrLen)
	cmn.UpdatePathOffsets(out, 0x12, 0x23)
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x23, 0x00}, out)
	assert.EqualValues(t, 0x12, cmn.CurrInfoF)
	assert.EqualValues(t, 0x23, cmn.CurrHopF)
}
