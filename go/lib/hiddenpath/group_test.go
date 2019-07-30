package hpGroup

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

var (
	as_110 = xtest.MustParseAS("ff00:0:110")
	ia_110 = xtest.MustParseIA("1-ff00:0:110")
	ia_111 = xtest.MustParseIA("1-ff00:0:111")
	ia_112 = xtest.MustParseIA("1-ff00:0:112")
	ia_113 = xtest.MustParseIA("1-ff00:0:113")
	ia_114 = xtest.MustParseIA("1-ff00:0:114")
	ia_115 = xtest.MustParseIA("1-ff00:0:115")
)

func TestUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Modify         func() []byte
		ExpectedErrMsg string
	}{
		"valid": {
			Modify: func() []byte {
				return []byte(testCfg)
			},
			ExpectedErrMsg: "",
		},
		"invalid GroupId format": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, "ff00:0:110-69b5", "invalid", 1))
			},
			ExpectedErrMsg: `Invalid GroupId format GroupId="invalid"`,
		},
		"invalid GroupId AS": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, "ff00:0:110", "invalid", 1))
			},
			ExpectedErrMsg: `Unable to parse AS`,
		},
		"invalid GroupId suffix": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, "69b5", "invalid", 1))
			},
			ExpectedErrMsg: `Invalid GroupId suffix suffix="invalid"`,
		},
		"version missing": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, `"Version": 1,`, "", 1))
			},
			ExpectedErrMsg: `Invalid version`,
		},
		"version invalid": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, `"Version": 1,`, `"Version": 0,`, 1))
			},
			ExpectedErrMsg: `Invalid version`,
		},
		"owner mismatch": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, "ff00:0:110", "ffaa:0:110", 1))
			},
			ExpectedErrMsg: `Owner mismatch OwnerAS="ff00:0:110" GroupId.OwnerAS="ffaa:0:110"`,
		},
		"invalid Owner": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, "1-ff00:0:110", "invalid", 1))
			},
			ExpectedErrMsg: `Invalid ISD-AS raw="invalid"`,
		},
		"invalid Writer": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, "1-ff00:0:111", "invalid", 1))
			},
			ExpectedErrMsg: `Invalid ISD-AS raw="invalid"`,
		},
		"invalid Reader": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, "1-ff00:0:114", "invalid", 1))
			},
			ExpectedErrMsg: `Invalid ISD-AS raw="invalid"`,
		},
		"invalid Registry": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, "1-ff00:0:115", "invalid", 1))
			},
			ExpectedErrMsg: `Invalid ISD-AS raw="invalid"`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var parsed Group
			err := json.Unmarshal(test.Modify(), &parsed)
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
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
			OwnerAS: as_110,
			GroupId: 0x69b5,
		},
		Version:    0x1,
		OwnerISD:   0x1,
		Writers:    []addr.IAInt{ia_111.IAInt(), ia_112.IAInt()},
		Readers:    []addr.IAInt{ia_113.IAInt(), ia_114.IAInt()},
		Registries: []addr.IAInt{ia_110.IAInt(), ia_111.IAInt(), ia_115.IAInt()},
	}
	cfg := &Group{}
	err := json.Unmarshal([]byte(testCfg), cfg)
	require.NoError(t, err)
	msg := cfg.ToMsg()
	assert.Equal(t, expected, msg)
	cfg2 := FromMsg(msg)
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
			Func:     cfg.IsWriter,
			Expected: true,
		},
		"not has writer": {
			IA:       cfg.Readers[0],
			Func:     cfg.IsWriter,
			Expected: false,
		},
		"has reader": {
			IA:       cfg.Readers[0],
			Func:     cfg.IsReader,
			Expected: true,
		},
		"not has reader": {
			IA:       cfg.Writers[0],
			Func:     cfg.IsReader,
			Expected: false,
		},
		"has registry": {
			IA:       cfg.Registries[0],
			Func:     cfg.IsRegistry,
			Expected: true,
		},
		"not has registry": {
			IA:       cfg.Writers[1],
			Func:     cfg.IsRegistry,
			Expected: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.Expected, test.Func(test.IA))
		})
	}
}
