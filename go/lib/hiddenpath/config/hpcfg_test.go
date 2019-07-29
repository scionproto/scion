package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
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
		"invalid GroupId AS": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, "ff00:0:110", "x", 1))
			},
			ExpectedErrMsg: `Unable to parse AS`,
		},
		"invalid GroupId suffix": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, "69b5", "x", 1))
			},
			ExpectedErrMsg: `Invalid GroupId suffix suffix="x"`,
		},
		"version missing": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, `"Version": 1,`, "", 1))
			},
			ExpectedErrMsg: `Version missing`,
		},
		"owner mismatch": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, "ff00:0:110", "ffaa:0:110", 1))
			},
			ExpectedErrMsg: `Owner mismatch OwnerAS="ff00:0:110" GroupId.OwnerAS="ffaa:0:110"`,
		},
		"invalid Owner": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, "1-ff00:0:110", "x", 1))
			},
			ExpectedErrMsg: `Invalid ISD-AS raw="x"`,
		},
		"invalid Writer": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, "1-ff00:0:111", "x", 1))
			},
			ExpectedErrMsg: `Invalid ISD-AS raw="x"`,
		},
		"invalid Reader": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, "1-ff00:0:114", "x", 1))
			},
			ExpectedErrMsg: `Invalid ISD-AS raw="x"`,
		},
		"invalid Registry": {
			Modify: func() []byte {
				return []byte(strings.Replace(testCfg, "1-ff00:0:115", "x", 1))
			},
			ExpectedErrMsg: `Invalid ISD-AS raw="x"`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var parsed HPCfg
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
	cfg := &HPCfg{}
	err := json.Unmarshal([]byte(testCfg), cfg)
	require.NoError(t, err)
	b, err := json.MarshalIndent(cfg, "", "    ")
	require.NoError(t, err)
	assert.Equal(t, testCfg, string(b))
}

func TestToMsgFromMsg(t *testing.T) {
	expected := &path_mgmt.HPCfg{
		GroupId: &path_mgmt.HPGroupId{
			OwnerAS: 0xff0000000110,
			GroupId: 0x69b5,
		},
		Version:    0x1,
		OwnerISD:   0x1,
		Writers:    []addr.IAInt{0x1ff0000000111, 0x1ff0000000112},
		Readers:    []addr.IAInt{0x1ff0000000113, 0x1ff0000000114},
		Registries: []addr.IAInt{0x1ff0000000110, 0x1ff0000000111, 0x1ff0000000115},
	}
	cfg := &HPCfg{}
	err := json.Unmarshal([]byte(testCfg), cfg)
	require.NoError(t, err)
	msg := cfg.ToMsg()
	assert.Equal(t, expected, msg)
	cfg2 := FromMsg(msg)
	assert.Equal(t, cfg, cfg2)
}

func TestHas(t *testing.T) {
	cfg := &HPCfg{}
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
			if test.Expected {
				assert.True(t, test.Func(test.IA))
			} else {
				assert.False(t, test.Func(test.IA))
			}
		})
	}
}
