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

package hiddenpath

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/xtest"
)

var testCfg = `{
    "GroupID": "ff00:0:110-69b5",
    "Version": 1,
    "Owner": "1-ff00:0:110",
    "Writers": [
        "1-ff00:0:111",
        "1-ff00:0:112"
    ],
    "Readers": [
        "1-ff00:0:113",
        "1-ff00:0:114"
    ],
    "Registries": [
        "1-ff00:0:110",
        "1-ff00:0:111",
        "1-ff00:0:115"
    ]
}`

var testGroup = Group{
	Id: GroupId{
		OwnerAS: as110,
		Suffix:  0x69b5,
	},
	Version:    1,
	Owner:      ia110,
	Writers:    []addr.IA{ia111, ia112},
	Readers:    []addr.IA{ia113, ia114},
	Registries: []addr.IA{ia110, ia111, ia115},
}

var (
	as110 = xtest.MustParseAS("ff00:0:110")
	ia110 = xtest.MustParseIA("1-ff00:0:110")
	ia111 = xtest.MustParseIA("1-ff00:0:111")
	ia112 = xtest.MustParseIA("1-ff00:0:112")
	ia113 = xtest.MustParseIA("1-ff00:0:113")
	ia114 = xtest.MustParseIA("1-ff00:0:114")
	ia115 = xtest.MustParseIA("1-ff00:0:115")
)

func TestUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Modify         func() string
		ExpectedErrMsg string
		ExpectedGroup  func() Group
	}{
		"valid": {
			Modify: func() string {
				return testCfg
			},
			ExpectedErrMsg: "",
			ExpectedGroup:  func() Group { return testGroup },
		},
		"missing GroupId": {
			Modify: func() string {
				return strings.Replace(testCfg, `"GroupID": "ff00:0:110-69b5",`, "", 1)
			},
			ExpectedErrMsg: `Missing GroupId`,
		},
		"invalid GroupId format": {
			Modify: func() string {
				return strings.Replace(testCfg, "ff00:0:110-69b5", "invalid", 1)
			},
			ExpectedErrMsg: `Invalid GroupId format GroupId="invalid"`,
		},
		"invalid GroupId AS": {
			Modify: func() string {
				return strings.Replace(testCfg, "ff00:0:110", "invalid", 1)
			},
			ExpectedErrMsg: `Unable to parse AS`,
		},
		"invalid GroupId suffix": {
			Modify: func() string {
				return strings.Replace(testCfg, "69b5", "invalid", 1)
			},
			ExpectedErrMsg: `Invalid GroupId suffix Suffix="invalid"`,
		},
		"missing version": {
			Modify: func() string {
				return strings.Replace(testCfg, `"Version": 1,`, "", 1)
			},
			ExpectedErrMsg: `Invalid version`,
		},
		"invalid version": {
			Modify: func() string {
				return strings.Replace(testCfg, `"Version": 1,`, `"Version": 0,`, 1)
			},
			ExpectedErrMsg: `Invalid version`,
		},
		"missing Owner": {
			Modify: func() string {
				return strings.Replace(testCfg, `"Owner": "1-ff00:0:110",`, "", 1)
			},
			ExpectedErrMsg: `Missing Owner`,
		},
		"invalid Owner": {
			Modify: func() string {
				return strings.Replace(testCfg, "1-ff00:0:110", "invalid", 1)
			},
			ExpectedErrMsg: `Invalid ISD-AS raw="invalid"`,
		},
		"owner mismatch": {
			Modify: func() string {
				return strings.Replace(testCfg, "ff00:0:110", "ffaa:0:110", 1)
			},
			ExpectedErrMsg: `Owner mismatch OwnerAS="ff00:0:110" GroupId.OwnerAS="ffaa:0:110"`,
		},
		"missing Writers": {
			Modify: func() string {
				g := testGroup
				g.Writers = nil
				b, _ := json.Marshal(g)
				return string(b)
			},
			ExpectedErrMsg: `Writer section cannot be empty`,
		},
		"empty Writers": {
			Modify: func() string {
				g := testGroup
				g.Writers = []addr.IA{}
				b, _ := json.Marshal(g)
				return string(b)
			},
			ExpectedErrMsg: `Writer section cannot be empty`,
		},
		"invalid Writer": {
			Modify: func() string {
				return strings.Replace(testCfg, "1-ff00:0:111", "invalid", 1)
			},
			ExpectedErrMsg: `Invalid ISD-AS raw="invalid"`,
		},
		"missing Readers ok": {
			Modify: func() string {
				g := testGroup
				g.Readers = nil
				b, _ := json.Marshal(g)
				return string(b)
			},
			ExpectedGroup: func() Group {
				g := testGroup
				g.Readers = nil
				return g
			},
		},
		"empty Readers ok": {
			Modify: func() string {
				g := testGroup
				g.Readers = []addr.IA{}
				b, _ := json.Marshal(g)
				return string(b)
			},
			ExpectedGroup: func() Group {
				g := testGroup
				g.Readers = []addr.IA{}
				return g
			},
		},
		"invalid Reader": {
			Modify: func() string {
				return strings.Replace(testCfg, "1-ff00:0:114", "invalid", 1)
			},
			ExpectedErrMsg: `Invalid ISD-AS raw="invalid"`,
		},
		"missing Registries": {
			Modify: func() string {
				g := testGroup
				g.Registries = nil
				b, _ := json.Marshal(g)
				return string(b)
			},
			ExpectedErrMsg: `Registry section cannot be empty`,
		},
		"empty Registries": {
			Modify: func() string {
				g := testGroup
				g.Registries = []addr.IA{}
				b, _ := json.Marshal(g)
				return string(b)
			},
			ExpectedErrMsg: `Registry section cannot be empty`,
		},
		"invalid Registry": {
			Modify: func() string {
				return strings.Replace(testCfg, "1-ff00:0:115", "invalid", 1)
			},
			ExpectedErrMsg: `Invalid ISD-AS raw="invalid"`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var parsed Group
			err := json.Unmarshal([]byte(test.Modify()), &parsed)
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
				require.Equal(t, test.ExpectedGroup(), parsed)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

func TestUnmarshalMarshal(t *testing.T) {
	cfg := &Group{}
	err := json.Unmarshal([]byte(testCfg), cfg)
	require.NoError(t, err)
	b, err := json.MarshalIndent(cfg, "", "    ")
	require.NoError(t, err)
	assert.Equal(t, testCfg, string(b))
}

func TestToMsgFromMsg(t *testing.T) {
	expected := &path_mgmt.HPCfg{
		GroupId: &path_mgmt.HPGroupId{
			OwnerAS: as110,
			GroupId: 0x69b5,
		},
		Version:    0x1,
		OwnerISD:   0x1,
		Writers:    []addr.IAInt{ia111.IAInt(), ia112.IAInt()},
		Readers:    []addr.IAInt{ia113.IAInt(), ia114.IAInt()},
		Registries: []addr.IAInt{ia110.IAInt(), ia111.IAInt(), ia115.IAInt()},
	}
	cfg := &Group{}
	err := json.Unmarshal([]byte(testCfg), cfg)
	require.NoError(t, err)
	msg := cfg.ToMsg()
	assert.Equal(t, expected, msg)
	cfg2 := GroupFromMsg(msg)
	assert.Equal(t, cfg, cfg2)
}

func TestHas(t *testing.T) {
	cfg := &Group{}
	err := json.Unmarshal([]byte(testCfg), cfg)
	require.NoError(t, err)

	tests := map[string]struct {
		IA       addr.IA
		Func     func(addr.IA) bool
		Expected bool
	}{
		"has writer": {
			IA:       cfg.Writers[0],
			Func:     cfg.HasWriter,
			Expected: true,
		},
		"not has writer": {
			IA:       cfg.Readers[0],
			Func:     cfg.HasWriter,
			Expected: false,
		},
		"has reader": {
			IA:       cfg.Readers[0],
			Func:     cfg.HasReader,
			Expected: true,
		},
		"not has reader": {
			IA:       cfg.Writers[0],
			Func:     cfg.HasReader,
			Expected: false,
		},
		"has registry": {
			IA:       cfg.Registries[0],
			Func:     cfg.HasRegistry,
			Expected: true,
		},
		"not has registry": {
			IA:       cfg.Writers[1],
			Func:     cfg.HasRegistry,
			Expected: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.Expected, test.Func(test.IA))
		})
	}
}
