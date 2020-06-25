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

package reservation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestSegmentIDFromRaw(t *testing.T) {
	id, err := SegmentIDFromRaw(xtest.MustParseHexString("ffaa00001101facecafe"))
	require.NoError(t, err)
	require.Equal(t, xtest.MustParseAS("ffaa:0:1101"), id.ASID)
	require.Equal(t, xtest.MustParseHexString("facecafe"), id.Suffix[:])
}

func TestSegmentIDRead(t *testing.T) {
	reference := SegmentID{
		ASID: xtest.MustParseAS("ffaa:0:1101"),
	}
	copy(reference.Suffix[:], xtest.MustParseHexString("facecafe"))
	raw := make([]byte, SegmentIDLen)
	n, err := reference.Read(raw)
	require.NoError(t, err)
	require.Equal(t, SegmentIDLen, n)
	require.Equal(t, xtest.MustParseHexString("ffaa00001101facecafe"), raw)
}

func TestE2EIDFromRaw(t *testing.T) {
	raw := xtest.MustParseHexString("ffaa00001101facecafedeadbeeff00d")
	id, err := E2EIDFromRaw(raw)
	require.NoError(t, err)
	require.Equal(t, xtest.MustParseAS("ffaa:0:1101"), id.ASID)
	require.Equal(t, xtest.MustParseHexString("facecafedeadbeeff00d"), id.Suffix[:])
}

func TestE2EIDRead(t *testing.T) {
	reference := E2EID{
		ASID: xtest.MustParseAS("ffaa:0:1101"),
	}
	copy(reference.Suffix[:], xtest.MustParseHexString("facecafedeadbeeff00d"))
	raw := make([]byte, E2EIDLen)
	n, err := reference.Read(raw)
	require.NoError(t, err)
	require.Equal(t, E2EIDLen, n)
	require.Equal(t, xtest.MustParseHexString("ffaa00001101facecafedeadbeeff00d"), raw)
}

func TestTickFromTime(t *testing.T) {
	require.Equal(t, Tick(0), TickFromTime(time.Unix(0, 0)))
	require.Equal(t, Tick(0), TickFromTime(time.Unix(3, 999999)))
	require.Equal(t, Tick(1), TickFromTime(time.Unix(4, 0)))
}

func TestTickToTime(t *testing.T) {
	require.Equal(t, time.Unix(0, 0), Tick(0).ToTime())
	require.Equal(t, time.Unix(4, 0), Tick(1).ToTime())
	require.Equal(t, time.Unix(0, 0), TickFromTime(time.Unix(0, 0)).ToTime())
	require.Equal(t, time.Unix(0, 0), TickFromTime(time.Unix(3, 999999)).ToTime())
	require.Equal(t, time.Unix(4, 0), TickFromTime(time.Unix(4, 0)).ToTime())
}

func TestValidateBWCls(t *testing.T) {
	for i := 0; i < 64; i++ {
		c := BWCls(i)
		err := c.Validate()
		require.NoError(t, err)
	}
	c := BWCls(64)
	err := c.Validate()
	require.Error(t, err)
}

func TestValidateRLC(t *testing.T) {
	for i := 0; i < 64; i++ {
		c := RLC(i)
		err := c.Validate()
		require.NoError(t, err)
	}
	c := RLC(64)
	err := c.Validate()
	require.Error(t, err)
}

func TestValidateIndexNumber(t *testing.T) {
	for i := 0; i < 16; i++ {
		idx := IndexNumber(i)
		err := idx.Validate()
		require.NoError(t, err)
	}
	idx := IndexNumber(16)
	err := idx.Validate()
	require.Error(t, err)
}

func TestIndexNumberArithmetic(t *testing.T) {
	var idx IndexNumber = 1
	x := idx.Add(IndexNumber(15))
	require.Equal(t, IndexNumber(0), x)
	x = idx.Sub(IndexNumber(2))
	require.Equal(t, IndexNumber(15), x)
	// distance from 2 to 0 = 0 - 2 = 14 mod 16
	x = IndexNumber(2)
	distance := IndexNumber(0).Sub(x)
	require.Equal(t, IndexNumber(14), distance)
	// distance from 2 to 4
	distance = IndexNumber(4).Sub(x)
	require.Equal(t, IndexNumber(2), distance)
}

func TestValidatePathType(t *testing.T) {
	validTypes := []PathType{
		DownPath,
		UpPath,
		PeeringDownPath,
		PeeringUpPath,
		E2EPath,
		CorePath,
	}
	for _, vt := range validTypes {
		pt := PathType(vt)
		err := pt.Validate()
		require.NoError(t, err)
	}
	pt := PathType(UnknownPath)
	err := pt.Validate()
	require.Error(t, err)

	pt = PathType(CorePath + 1)
	err = pt.Validate()
	require.Error(t, err)
}

func TestValidateInfoField(t *testing.T) {
	infoField := InfoField{
		ExpirationTick: 0,
		BWCls:          0,
		RLC:            0,
		Idx:            0,
		PathType:       CorePath,
	}
	err := infoField.Validate()
	require.NoError(t, err)

	otherIF := infoField
	otherIF.BWCls = 64
	err = otherIF.Validate()
	require.Error(t, err)

	otherIF = infoField
	otherIF.RLC = 64
	err = otherIF.Validate()
	require.Error(t, err)

	otherIF = infoField
	otherIF.Idx = 16
	err = otherIF.Validate()
	require.Error(t, err)

	otherIF = infoField
	otherIF.PathType = CorePath + 1
	err = otherIF.Validate()
	require.Error(t, err)
}

func TestInfoFieldFromRaw(t *testing.T) {
	reference := newInfoField()
	rawReference := newInfoFieldRaw()
	info, err := InfoFieldFromRaw(rawReference)
	require.NoError(t, err)
	require.Equal(t, reference, *info)
}

func TestInfoFieldRead(t *testing.T) {
	reference := newInfoField()
	rawReference := newInfoFieldRaw()
	raw := make([]byte, InfoFieldLen)
	// pollute the buffer with garbage
	for i := 0; i < InfoFieldLen; i++ {
		raw[i] = byte(i % 256)
	}
	n, err := reference.Read(raw)
	require.NoError(t, err)
	require.Equal(t, InfoFieldLen, n)
	require.Equal(t, rawReference, raw)
}

func TestValidatePathEndProperties(t *testing.T) {
	for i := 0; i < 4; i++ {
		pep := PathEndProps(i)
		err := pep.Validate()
		require.NoError(t, err)
	}
	pep := PathEndProps(4)
	err := pep.Validate()
	require.Error(t, err)

	for i := 0; i < 4; i++ {
		pep := PathEndProps(i << 4)
		err := pep.Validate()
		require.NoError(t, err)
	}
	pep = PathEndProps(4 << 4)
	err = pep.Validate()
	require.Error(t, err)

	pep = PathEndProps(0x10 | 0x04)
	err = pep.Validate()
	require.Error(t, err)
}

func TestValidateToken(t *testing.T) {
	tok := newToken()
	err := tok.Validate()
	require.NoError(t, err)
	tok.HopFields = []spath.HopField{}
	err = tok.Validate()
	require.Error(t, err)
}

func TestTokenLen(t *testing.T) {
	tok := newToken()
	require.Equal(t, len(newTokenRaw()), tok.Len())
}

func TestTokenFromRaw(t *testing.T) {
	referenceRaw := newTokenRaw()
	reference := newToken()
	tok, err := TokenFromRaw(referenceRaw)
	require.NoError(t, err)
	require.Equal(t, reference, *tok)

	// buffer too small
	_, err = TokenFromRaw(referenceRaw[:3])
	require.Error(t, err)

	// one hop field less
	tok, err = TokenFromRaw(referenceRaw[:len(referenceRaw)-spath.HopFieldLength])
	require.NoError(t, err)
	require.Len(t, tok.HopFields, len(reference.HopFields)-1)
}
func TestTokenRead(t *testing.T) {
	tok := newToken()
	rawReference := newTokenRaw()
	buf := make([]byte, len(rawReference))
	c, err := tok.Read(buf)
	require.NoError(t, err)
	require.Equal(t, len(buf), c)
	require.Equal(t, rawReference, buf)

	// buffer too small
	_, err = tok.Read(buf[:len(rawReference)-1])
	require.Error(t, err)
}

func TestTokenToRaw(t *testing.T) {
	tok := newToken()
	raw := newTokenRaw()
	require.Equal(t, raw, tok.ToRaw())
}

func newInfoField() InfoField {
	return InfoField{
		ExpirationTick: 384555855,
		BWCls:          13,
		RLC:            4,
		Idx:            2,
		PathType:       E2EPath,
	}
}

func newInfoFieldRaw() []byte {
	return xtest.MustParseHexString("16ebdb4f0d042500")
}

func newToken() Token {
	return Token{
		InfoField: newInfoField(),
		HopFields: []spath.HopField{
			{
				Xover:       false,
				ExpTime:     spath.DefaultHopFExpiry,
				ConsIngress: 1,
				ConsEgress:  2,
				Mac:         xtest.MustParseHexString("bad1ce"),
			},
			{
				Xover:       false,
				ExpTime:     spath.DefaultHopFExpiry,
				ConsIngress: 1,
				ConsEgress:  2,
				Mac:         xtest.MustParseHexString("facade"),
			},
		},
	}
}
func newTokenRaw() []byte {
	return xtest.MustParseHexString("16ebdb4f0d042500003f001002bad1ce003f001002facade")
}
