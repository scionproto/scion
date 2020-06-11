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

package ctrl_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestNewX509SignSrc(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		expected := ctrl.X509SignSrc{
			IA:           xtest.MustParseIA("1-ff00:0:110"),
			Base:         1,
			Serial:       15,
			SubjectKeyID: xtest.MustParseHexString("deadbeef"),
		}

		input := []byte{
			0x00, 0x01, // ISD
			0xff, 0x00, 0x00, 0x00, 0x01, 0x10, // AS
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Base
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, // Serial
			0xde, 0xad, 0xbe, 0xef, // Subject Key ID
		}
		src, err := ctrl.NewX509SignSrc(input)
		require.NoError(t, err)
		assert.Equal(t, expected, src)
	})
	t.Run("too short", func(t *testing.T) {
		_, err := ctrl.NewX509SignSrc(make([]byte, addr.IABytes))
		assert.Error(t, err)
	})
}

func TestX509SignSrcPack(t *testing.T) {
	src := ctrl.X509SignSrc{
		IA:           xtest.MustParseIA("1-ff00:0:110"),
		Base:         2,
		Serial:       15,
		SubjectKeyID: xtest.MustParseHexString("deadbeef"),
	}

	expected := []byte{
		0x00, 0x01, // ISD
		0xff, 0x00, 0x00, 0x00, 0x01, 0x10, // AS
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // Base
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, // Serial
		0xde, 0xad, 0xbe, 0xef, // Subject Key ID
	}
	assert.Equal(t, expected, src.Pack())
}

func TestX509SignSrcIsZero(t *testing.T) {
	testCases := map[string]struct {
		Src    ctrl.X509SignSrc
		IsZero bool
	}{
		"zero value": {
			Src:    ctrl.X509SignSrc{},
			IsZero: true,
		},
		"empty subject key id": {
			Src:    ctrl.X509SignSrc{SubjectKeyID: []byte{}},
			IsZero: true,
		},
		"ia set": {
			Src:    ctrl.X509SignSrc{IA: xtest.MustParseIA("1-ff00:0:110")},
			IsZero: false,
		},
		"subject key id set": {
			Src:    ctrl.X509SignSrc{SubjectKeyID: []byte{1}},
			IsZero: false,
		},
		"base set": {
			Src:    ctrl.X509SignSrc{Base: 1},
			IsZero: false,
		},
		"serial set": {
			Src:    ctrl.X509SignSrc{Serial: 15},
			IsZero: false,
		},
		"all set": {
			Src: ctrl.X509SignSrc{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				Base:         1,
				Serial:       1,
				SubjectKeyID: []byte{1},
			},
			IsZero: false,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.IsZero, tc.Src.IsZero())
		})
	}
}

func TestX509SignSrcEqual(t *testing.T) {
	testCases := map[string]struct {
		Src   ctrl.X509SignSrc
		Other ctrl.X509SignSrc
		Equal bool
	}{
		"both zero": {
			Src:   ctrl.X509SignSrc{},
			Other: ctrl.X509SignSrc{},
			Equal: true,
		},
		"both same": {
			Src: ctrl.X509SignSrc{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				Base:         1,
				Serial:       15,
				SubjectKeyID: []byte{1},
			},
			Other: ctrl.X509SignSrc{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				Base:         1,
				Serial:       15,
				SubjectKeyID: []byte{1},
			},
			Equal: true,
		},
		"both same, zero and nil skid": {
			Src: ctrl.X509SignSrc{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				Base:         1,
				Serial:       15,
				SubjectKeyID: []byte{},
			},
			Other: ctrl.X509SignSrc{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				Base:         1,
				Serial:       15,
				SubjectKeyID: nil,
			},
			Equal: true,
		},
		"one non-zero": {
			Src:   ctrl.X509SignSrc{IA: xtest.MustParseIA("1-ff00:0:110")},
			Other: ctrl.X509SignSrc{},
			Equal: false,
		},
		"different ia": {
			Src: ctrl.X509SignSrc{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				Base:         1,
				Serial:       15,
				SubjectKeyID: []byte{1},
			},
			Other: ctrl.X509SignSrc{
				IA:           xtest.MustParseIA("1-ff00:0:111"),
				Base:         1,
				Serial:       15,
				SubjectKeyID: []byte{1},
			},
			Equal: false,
		},
		"different skid": {
			Src: ctrl.X509SignSrc{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				Base:         1,
				Serial:       15,
				SubjectKeyID: []byte{1},
			},
			Other: ctrl.X509SignSrc{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				Base:         1,
				Serial:       15,
				SubjectKeyID: []byte{1, 2},
			},
			Equal: false,
		},
		"different base": {
			Src: ctrl.X509SignSrc{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				Base:         1,
				Serial:       15,
				SubjectKeyID: []byte{},
			},
			Other: ctrl.X509SignSrc{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				Base:         2,
				Serial:       15,
				SubjectKeyID: nil,
			},
			Equal: false,
		},
		"different serial": {
			Src: ctrl.X509SignSrc{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				Base:         1,
				Serial:       15,
				SubjectKeyID: []byte{},
			},
			Other: ctrl.X509SignSrc{
				IA:           xtest.MustParseIA("1-ff00:0:110"),
				Base:         1,
				Serial:       23,
				SubjectKeyID: nil,
			},
			Equal: false,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.Equal, tc.Src.Equal(tc.Other))
		})
	}
}

func TestX509SignSrcString(t *testing.T) {
	src := ctrl.X509SignSrc{
		IA:           xtest.MustParseIA("1-ff00:0:110"),
		Base:         1,
		Serial:       15,
		SubjectKeyID: xtest.MustParseHexString("deadbeef"),
	}
	assert.Equal(t, "ISD-AS: 1-ff00:0:110 TRC: B1-S15 SubjectKeyID: DE AD BE EF", src.String())
}
