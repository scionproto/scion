// Copyright 2021 Anapaya Systems
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

package flag_test

import (
	"encoding/json"
	"net/netip"
	"os"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/private/app/env"
	"github.com/scionproto/scion/private/app/flag"
)

func TestSCIONEnvironment(t *testing.T) {
	setupFile := func(t *testing.T, envFlags *flag.SCIONEnvironment) {
		f, err := os.CreateTemp(t.TempDir(), "env.json")
		require.NoError(t, err)
		fName := f.Name()
		t.Cleanup(func() { os.Remove(fName) })
		e := env.SCION{
			General: env.General{
				DefaultIA: addr.MustParseIA("1-ff00:0:110"),
			},
			ASes: map[addr.IA]env.AS{
				addr.MustParseIA("1-ff00:0:110"): {
					DaemonAddress: "scion_file:1234",
				},
			},
		}
		require.NoError(t, json.NewEncoder(f).Encode(e))
		require.NoError(t, f.Close())
		envFlags.SetFilePath(fName)
	}
	noFile := func(_ *testing.T, envFlags *flag.SCIONEnvironment) {
		envFlags.SetFilePath("/non-existing")
	}
	setupEnv := func(t *testing.T) {
		tempEnv(t, "SCION_DAEMON", "scion_env:1234")
		tempEnv(t, "SCION_LOCAL_ADDR", "10.0.42.0")
	}
	noEnv := func(t *testing.T) {}
	setupFlags := func(t *testing.T, fs *pflag.FlagSet) {
		err := fs.Parse([]string{
			"--sciond", "scion:1234",
			"--local", "10.0.0.42",
		})
		require.NoError(t, err)
	}
	noFlags := func(t *testing.T, fs *pflag.FlagSet) {
		require.NoError(t, fs.Parse([]string{}))
	}
	testCases := map[string]struct {
		flags      func(t *testing.T, fs *pflag.FlagSet)
		file       func(t *testing.T, envFlags *flag.SCIONEnvironment)
		env        func(t *testing.T)
		daemon     string
		dispatcher string
		local      netip.Addr
	}{
		"no flag, no file, no env, defaults only": {
			flags:  noFlags,
			env:    noEnv,
			file:   noFile,
			daemon: daemon.DefaultAPIAddress,
			local:  netip.Addr{},
		},
		"flag values set": {
			flags:  setupFlags,
			env:    noEnv,
			file:   noFile,
			daemon: "scion:1234",
			local:  netip.MustParseAddr("10.0.0.42"),
		},
		"env values set": {
			flags:  noFlags,
			env:    setupEnv,
			file:   noFile,
			daemon: "scion_env:1234",
			local:  netip.MustParseAddr("10.0.42.0"),
		},
		"file values set": {
			flags:  noFlags,
			env:    noEnv,
			file:   setupFile,
			daemon: "scion_file:1234",
			local:  netip.Addr{},
		},
		"all set, flag precedence": {
			flags:  setupFlags,
			env:    setupEnv,
			file:   setupFile,
			daemon: "scion:1234",
			local:  netip.MustParseAddr("10.0.0.42"),
		},
		"env set, file set, env precedence": {
			flags:  noFlags,
			env:    setupEnv,
			file:   setupFile,
			daemon: "scion_env:1234",
			local:  netip.MustParseAddr("10.0.42.0"),
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var env flag.SCIONEnvironment
			fs := pflag.NewFlagSet("testSet", pflag.ContinueOnError)
			env.Register(fs)
			tc.flags(t, fs)
			tc.env(t)
			tc.file(t, &env)
			require.NoError(t, env.LoadExternalVars())
			assert.Equal(t, tc.daemon, env.Daemon())
			assert.Equal(t, tc.local, env.Local())
		})
	}
}

// tempEnv sets an environment variable temporarily and remove it at the end of
// the test.
func tempEnv(t *testing.T, key, val string) {
	require.NoError(t, os.Setenv(key, val))
	t.Cleanup(func() { require.NoError(t, os.Unsetenv(key)) })
}
