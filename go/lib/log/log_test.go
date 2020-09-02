// Copyright 2018 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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

package log_test

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
)

func TestSetup(t *testing.T) {
	tests := map[string]struct {
		cfg       log.Config
		assertErr assert.ErrorAssertionFunc
	}{
		"empty, no error": {
			cfg:       log.Config{},
			assertErr: assert.NoError,
		},
		"invalid console level": {
			cfg:       log.Config{Console: log.ConsoleConfig{Level: "invalid"}},
			assertErr: assert.Error,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := log.Setup(test.cfg)
			test.assertErr(t, err)
		})
	}
}

func TestFmtCaller(t *testing.T) {
	assert.Equal(t, "...meblabla/bla_scion.go:12570", log.FmtCaller(
		zapcore.EntryCaller{
			Defined: true,
			File:    "verylongpathandfilenameblabla/bla_scion.go",
			Line:    12570,
		},
	), "test cut-off and fmt")
	assert.Equal(t, "exactthirty/bla_scion.go:12570", log.FmtCaller(
		zapcore.EntryCaller{
			Defined: true,
			File:    "exactthirty/bla_scion.go",
			Line:    12570,
		},
	), "test no cut-off full length")
	assert.Equal(t, "                   short.go:25", log.FmtCaller(
		zapcore.EntryCaller{
			Defined: true,
			File:    "short.go",
			Line:    25,
		},
	), "test fmt")
}

func TestLog(t *testing.T) {
	cfg := log.Config{
		Console: log.ConsoleConfig{Format: "human", Level: "debug"},
	}
	// redirect stderr to file.
	file, err := ioutil.TempFile("", "logtest")
	require.NoError(t, err)
	fName := file.Name()
	defer os.Remove(fName)
	origStderr := os.Stderr
	os.Stderr = file
	require.NoError(t, log.Setup(cfg))

	log.Info("msg1", "key1", "val1")
	logger := log.New("key2", "val2")
	logger.Debug("msg2", "key3", "val3")

	// restore stderr
	os.Stderr = origStderr
	require.NoError(t, file.Close())
	data, err := ioutil.ReadFile(fName)
	require.NoError(t, err)
	lines := strings.Split(string(data), "\n")
	require.Len(t, lines, 3)
	assert.Equal(t, `INFO	            log/log_test.go:92	msg1	{"key1": "val1"}`,
		lines[0][len(common.TimeFmt)+1:])
	assert.Equal(t,
		`DEBUG	            log/log_test.go:94	msg2	{"key2": "val2", "key3": "val3"}`,
		lines[1][len(common.TimeFmt)+1:])
}
