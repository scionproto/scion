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
	"runtime"
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
	defaultFile := func() env.SCION {
		return env.SCION{
			General: env.General{
				DefaultIA: addr.MustParseIA("1-ff00:0:110"),
			},
			ASes: map[addr.IA]env.AS{
				addr.MustParseIA("1-ff00:0:110"): {
					DaemonAddress: "scion_file:1234",
				},
			},
		}
	}
	setupFile := func(e env.SCION) func(t *testing.T, envFlags *flag.SCIONEnvironment) {
		return func(t *testing.T, envFlags *flag.SCIONEnvironment) {
			f, err := os.CreateTemp(t.TempDir(), "env.json")
			require.NoError(t, err)
			fName := f.Name()
			t.Cleanup(func() { os.Remove(fName) })
			require.NoError(t, json.NewEncoder(f).Encode(e))
			require.NoError(t, f.Close())
			envFlags.SetFilePath(fName)
		}
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
		daemonErr  bool
	}{
		"no flag, no file, no env, defaults only": {
			flags:  noFlags,
			env:    noEnv,
			file:   noFile,
			daemon: "",
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
			file:   setupFile(defaultFile()),
			daemon: "scion_file:1234",
			local:  netip.Addr{},
		},
		"all set, flag precedence": {
			flags:  setupFlags,
			env:    setupEnv,
			file:   setupFile(defaultFile()),
			daemon: "scion:1234",
			local:  netip.MustParseAddr("10.0.0.42"),
		},
		"env set, file set, env precedence": {
			flags:  noFlags,
			env:    setupEnv,
			file:   setupFile(defaultFile()),
			daemon: "scion_env:1234",
			local:  netip.MustParseAddr("10.0.42.0"),
		},
		"wrong --isd-as": {
			flags: func(t *testing.T, fs *pflag.FlagSet) {
				err := fs.Parse([]string{
					"--isd-as", "1-ff00:0:999",
				})
				require.NoError(t, err)
			},
			file:      setupFile(defaultFile()),
			env:       noEnv,
			daemonErr: true,
		},
		"--isd-as for AS without daemon": {
			flags: func(t *testing.T, fs *pflag.FlagSet) {
				err := fs.Parse([]string{
					"--isd-as", "1-ff00:0:120",
				})
				require.NoError(t, err)
			},
			file: setupFile(env.SCION{
				ASes: map[addr.IA]env.AS{
					addr.MustParseIA("1-ff00:0:120"): {
						DaemonAddress: "",
					},
				},
			}),
			env: noEnv,
		},
		"--isd-as for AS with default daemon": {
			flags: func(t *testing.T, fs *pflag.FlagSet) {
				err := fs.Parse([]string{
					"--isd-as", "1-ff00:0:120",
				})
				require.NoError(t, err)
			},
			file: setupFile(env.SCION{
				ASes: map[addr.IA]env.AS{
					addr.MustParseIA("1-ff00:0:120"): {
						DaemonAddress: "default",
					},
				},
			}),
			env:    noEnv,
			daemon: daemon.DefaultAPIAddress,
		},
		"wrong default ISD-AS": {
			flags: noFlags,
			file: setupFile(func() env.SCION {
				e := defaultFile()
				e.General.DefaultIA = addr.MustParseIA("1-ff00:0:999")
				return e
			}()),
			env:       noEnv,
			daemonErr: true,
		},
		"default ISD-AS for AS without daemon": {
			flags: noFlags,
			file: setupFile(env.SCION{
				General: env.General{
					DefaultIA: addr.MustParseIA("1-ff00:0:120"),
				},
				ASes: map[addr.IA]env.AS{
					addr.MustParseIA("1-ff00:0:120"): {
						DaemonAddress: "",
					},
				},
			}),
			env:       noEnv,
			daemonErr: false,
		}, "default ISD-AS for AS with default daemon": {
			flags: noFlags,
			file: setupFile(env.SCION{
				General: env.General{
					DefaultIA: addr.MustParseIA("1-ff00:0:120"),
				},
				ASes: map[addr.IA]env.AS{
					addr.MustParseIA("1-ff00:0:120"): {
						DaemonAddress: "default",
					},
				},
			}),
			env:    noEnv,
			daemon: daemon.DefaultAPIAddress,
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
			daemonAddr, err := env.Daemon()
			if tc.daemonErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.daemon, daemonAddr)
			}
			assert.Equal(t, tc.local, env.Local())
		})
	}
}

func TestSCIONEnvironmentMultipleASes(t *testing.T) {
	setupFileSingleAS := func(t *testing.T, envFlags *flag.SCIONEnvironment) {
		f, err := os.CreateTemp(t.TempDir(), "env.json")
		require.NoError(t, err)
		fName := f.Name()
		t.Cleanup(func() { os.Remove(fName) })
		e := env.SCION{
			// No DefaultIA set
			ASes: map[addr.IA]env.AS{
				addr.MustParseIA("1-ff00:0:110"): {
					DaemonAddress: "scion_single:1234",
				},
			},
		}
		require.NoError(t, json.NewEncoder(f).Encode(e))
		require.NoError(t, f.Close())
		envFlags.SetFilePath(fName)
	}

	setupFileMultipleASes := func(t *testing.T, envFlags *flag.SCIONEnvironment) {
		f, err := os.CreateTemp(t.TempDir(), "env.json")
		require.NoError(t, err)
		fName := f.Name()
		t.Cleanup(func() { os.Remove(fName) })
		e := env.SCION{
			// No DefaultIA set
			ASes: map[addr.IA]env.AS{
				addr.MustParseIA("1-ff00:0:110"): {
					DaemonAddress: "scion_as1:1234",
				},
				addr.MustParseIA("1-ff00:0:120"): {
					DaemonAddress: "scion_as2:1234",
				},
			},
		}
		require.NoError(t, json.NewEncoder(f).Encode(e))
		require.NoError(t, f.Close())
		envFlags.SetFilePath(fName)
	}

	setupFlagNonExistentAS := func(t *testing.T, fs *pflag.FlagSet) {
		err := fs.Parse([]string{"--isd-as", "1-ff00:0:999"})
		require.NoError(t, err)
	}

	setupFlagExistingAS := func(t *testing.T, fs *pflag.FlagSet) {
		err := fs.Parse([]string{"--isd-as", "1-ff00:0:110"})
		require.NoError(t, err)
	}

	noFlags := func(t *testing.T, fs *pflag.FlagSet) {
		require.NoError(t, fs.Parse([]string{}))
	}

	testCases := map[string]struct {
		flags     func(t *testing.T, fs *pflag.FlagSet)
		file      func(t *testing.T, envFlags *flag.SCIONEnvironment)
		daemon    string
		daemonErr bool
	}{
		"single AS in file, no defaultIA": {
			flags:  noFlags,
			file:   setupFileSingleAS,
			daemon: "scion_single:1234",
		},
		"multiple ASes in file, no defaultIA, error": {
			flags:     noFlags,
			file:      setupFileMultipleASes,
			daemonErr: true,
		},
		"multiple ASes in file, --isd-as set to existing AS": {
			flags:  setupFlagExistingAS,
			file:   setupFileMultipleASes,
			daemon: "scion_as1:1234",
		},
		"--isd-as set to non-existent AS, error": {
			flags:     setupFlagNonExistentAS,
			file:      setupFileMultipleASes,
			daemonErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var env flag.SCIONEnvironment
			fs := pflag.NewFlagSet("testSet", pflag.ContinueOnError)
			env.Register(fs)
			tc.flags(t, fs)
			tc.file(t, &env)
			require.NoError(t, env.LoadExternalVars())
			daemonAddr, err := env.Daemon()
			if tc.daemonErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.daemon, daemonAddr)
			}
		})
	}
}

// tempEnv sets an environment variable temporarily and remove it at the end of
// the test.
func tempEnv(t *testing.T, key, val string) {
	require.NoError(t, os.Setenv(key, val))
	t.Cleanup(func() { require.NoError(t, os.Unsetenv(key)) })
}

func TestSCIONEnvironmentConfigDir(t *testing.T) {
	defaultDir := ""
	if runtime.GOOS == "linux" {
		defaultDir = "/etc/scion"
	}

	testCases := map[string]struct {
		flags     []string
		configDir string
	}{
		"no flag": {
			flags:     []string{},
			configDir: defaultDir,
		},
		"config-dir flag set": {
			flags:     []string{"--config-dir", "/custom/path"},
			configDir: "/custom/path",
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var env flag.SCIONEnvironment
			fs := pflag.NewFlagSet("testSet", pflag.ContinueOnError)
			env.Register(fs)
			require.NoError(t, fs.Parse(tc.flags))
			assert.Equal(t, tc.configDir, env.ConfigDir())
		})
	}
}

func TestSCIONEnvironmentValidate(t *testing.T) {
	testCases := map[string]struct {
		flags   []string
		wantErr bool
	}{
		"sciond set": {
			flags:   []string{"--sciond", "127.0.0.1:30255"},
			wantErr: false,
		},
		"config-dir set": {
			flags:   []string{"--config-dir", "/custom/path"},
			wantErr: false,
		},
		"both flags set - sciond takes priority": {
			flags:   []string{"--sciond", "127.0.0.1:30255", "--config-dir", "/custom/path"},
			wantErr: false,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var env flag.SCIONEnvironment
			fs := pflag.NewFlagSet("testSet", pflag.ContinueOnError)
			env.Register(fs)
			require.NoError(t, fs.Parse(tc.flags))
			err := env.Validate()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
