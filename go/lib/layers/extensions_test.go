// Copyright 2019 ETH Zurich
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

package layers

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
)

func TestExtnOHPDecodeFromLayer(t *testing.T) {
	type TestCase struct {
		Extension      *Extension
		ErrorAssertion require.ErrorAssertionFunc
	}
	tests := map[string]TestCase{
		"bad payload": {
			Extension: mustCreateExtensionLayer([]byte{0, 2, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0}),
			ErrorAssertion: require.Error,
		},
		"good payload": {
			Extension:      mustCreateExtensionLayer([]byte{0, 1, 0, 0, 0, 0, 0, 0}),
			ErrorAssertion: require.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var extn ExtnOHP
			err := extn.DecodeFromLayer(test.Extension)
			test.ErrorAssertion(t, err)
		})
	}
}

func TestExtnSCMPDecodeFromLayer(t *testing.T) {
	type TestCase struct {
		Extension         *Extension
		ErrorAssertion    require.ErrorAssertionFunc
		ExpectedExtension ExtnSCMP
	}
	tests := map[string]TestCase{
		"good payload, no flags": {
			Extension:         mustCreateExtensionLayer([]byte{0, 1, 0, 0, 0, 0, 0, 0}),
			ExpectedExtension: ExtnSCMP{},
			ErrorAssertion:    require.NoError,
		},
		"good payload, error flag": {
			Extension:         mustCreateExtensionLayer([]byte{0, 1, 0, 0x01, 0, 0, 0, 0}),
			ExpectedExtension: ExtnSCMP{Error: true},
			ErrorAssertion:    require.NoError,
		},
		"good payload, all flags": {
			Extension:         mustCreateExtensionLayer([]byte{0, 1, 0, 0x03, 0, 0, 0, 0}),
			ExpectedExtension: ExtnSCMP{Error: true, HopByHop: true},
			ErrorAssertion:    require.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var extn ExtnSCMP
			err := extn.DecodeFromLayer(test.Extension)
			test.ErrorAssertion(t, err)
			assert.Equal(t, test.ExpectedExtension, extn, "extension must match")
		})
	}
}

func TestExtnUnkownDecodeFromLayer(t *testing.T) {
	type TestCase struct {
		Extension         *Extension
		ErrorAssertion    require.ErrorAssertionFunc
		ExpectedExtension ExtnUnknown
	}
	// Keep the loop s.t. it's more similar to the rest of the tests in here
	// and it's easier to add new tests
	tests := map[string]TestCase{
		"good payload length": {
			Extension: mustCreateExtensionLayer([]byte{0, 2, 3, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0}),
			ExpectedExtension: ExtnUnknown{Length: 13, TypeField: 3},
			ErrorAssertion:    require.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var extn ExtnUnknown
			err := extn.DecodeFromLayer(test.Extension)
			test.ErrorAssertion(t, err)
			assert.Equal(t, test.ExpectedExtension, extn, "extension must match")
		})
	}
}

func TestExtnPathTransDecodeFromLayer(t *testing.T) {
	type TestCase struct {
		Extension         *Extension
		ErrorAssertion    require.ErrorAssertionFunc
		ExpectedExtension ExtnPathTrans
		SkipPackCheck     bool
	}
	tests := map[string]TestCase{
		"good ipv4 host, no path": {
			Extension: mustCreateExtensionLayer([]byte{222, 2, 0, 1, 0, 1, 0xff, 0,
				0, 0, 0, 1, 192, 0, 2, 1}),
			ExpectedExtension: ExtnPathTrans{
				SrcIA:   mustParseIA("1-ff00:0:1"),
				SrcHost: addr.HostFromIPStr("192.0.2.1"),
				Path:    nil,
			},
			ErrorAssertion: require.NoError,
		},
		"good ipv6 host, no path": {
			Extension: mustCreateExtensionLayer([]byte{222, 4, 0, 2, 0, 1, 0xff, 0,
				0, 0, 0, 1, 0x20, 0x1, 0xd, 0xb8,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 1, 0, 0, 0, 0}),
			ExpectedExtension: ExtnPathTrans{
				SrcIA:   mustParseIA("1-ff00:0:1"),
				SrcHost: addr.HostFromIPStr("2001:db8::1"),
				Path:    nil,
			},
			ErrorAssertion: require.NoError,
		},
		"good service host, no path": {
			Extension: mustCreateExtensionLayer([]byte{222, 2, 0, 3, 0, 1, 0xff, 0,
				0, 0, 0, 1, 0, 1, 0, 0}),
			ExpectedExtension: ExtnPathTrans{
				SrcIA:   mustParseIA("1-ff00:0:1"),
				SrcHost: addr.SvcPS,
				Path:    nil,
			},
			ErrorAssertion: require.NoError,
		},
		"good no host, no path": {
			Extension: mustCreateExtensionLayer([]byte{222, 2, 0, 0, 0, 1, 0xff, 0,
				0, 0, 0, 1, 0, 0, 0, 0}),
			ExpectedExtension: ExtnPathTrans{
				SrcIA:   mustParseIA("1-ff00:0:1"),
				SrcHost: addr.HostNone{},
				Path:    nil,
			},
			ErrorAssertion: require.NoError,
		},
		"good ipv6 host, dummy path, check padding is handled correctly": {
			Extension: mustCreateExtensionLayer([]byte{222, 7, 0, 2, 0, 1, 0xff, 0,
				0, 0, 0, 1, 0x20, 0x1, 0xd, 0xb8,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 1, 0, 0, 0, 0,
				0x1, 0x5d, 0xde, 0x00, 0x00, 0, 1, 2,
				0x0, 0xbb, 0x00, 0x10, 0x02, 0xc0, 0xff, 0xee,
				0x0, 0xbb, 0x00, 0x20, 0x01, 0xf0, 0x0b, 0xa5,
			}),
			ExpectedExtension: ExtnPathTrans{
				SrcIA:   mustParseIA("1-ff00:0:1"),
				SrcHost: addr.HostFromIPStr("2001:db8::1"),
				Path: spath.New(common.RawBytes([]byte{0x1, 0x5d, 0xde, 0x00, 0x00, 0, 1, 2,
					0x0, 0xbb, 0x00, 0x10, 0x02, 0xc0, 0xff, 0xee,
					0x0, 0xbb, 0x00, 0x20, 0x01, 0xf0, 0x0b, 0xa5})),
			},
			ErrorAssertion: require.NoError,
		},
		"bad host type": {
			Extension: mustCreateExtensionLayer([]byte{222, 2, 0, 4, 0, 1, 0xff, 0,
				0, 0, 0, 1, 192, 0, 2, 1}),
			ErrorAssertion: require.Error,
			SkipPackCheck:  true,
		},
		"bad short ia": {
			Extension:      mustCreateExtensionLayer([]byte{222, 1, 0, 1, 0, 1, 0xff, 0}),
			ErrorAssertion: require.Error,
			SkipPackCheck:  true,
		},
		"bad short ipv6 addr": {
			Extension: mustCreateExtensionLayer([]byte{222, 3, 0, 2, 0, 1, 0xff, 0,
				0, 0, 0, 1, 0x20, 0x1, 0xD, 0xB8,
				0, 0, 0, 0, 0, 0, 0, 0}),
			ErrorAssertion: require.Error,
			SkipPackCheck:  true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var extn ExtnPathTrans
			err := extn.DecodeFromLayer(test.Extension)
			test.ErrorAssertion(t, err)

			// Helper for comparison: compare only raw path bytes
			type extnFlattened struct {
				ia      addr.IA
				host    addr.HostAddr
				pathRaw []byte
			}
			extnToCompare := func(o *ExtnPathTrans) extnFlattened {
				var p []byte
				if o.Path != nil {
					p = o.Path.Raw
				}
				return extnFlattened{o.SrcIA, o.SrcHost, p}
			}

			assert.Equal(t, extnToCompare(&test.ExpectedExtension), extnToCompare(&extn), "extension must match")

			if !test.SkipPackCheck {
				packed, err := test.ExpectedExtension.Pack()
				if err != nil {
					panic(err)
				}
				assert.Equal(t, test.Extension.Data, []byte(packed), "packed extension must match")
			}
		})
	}

}

func mustCreateExtensionLayer(b []byte) *Extension {
	var extn Extension
	if err := extn.DecodeFromBytes(b, gopacket.NilDecodeFeedback); err != nil {
		panic(err)
	}
	return &extn
}

func mustParseIA(s string) addr.IA {
	ia, err := addr.IAFromString(s)
	if err != nil {
		panic(err)
	}
	return ia
}
