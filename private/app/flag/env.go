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

package flag

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"runtime"
	"sync"

	"github.com/spf13/pflag"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/app/env"
)

const (
	defaultDaemon = daemon.DefaultAPIAddress

	defaultEnvironmentFile = "/etc/scion/environment.json"

	defaultConfigDirLinux = "/etc/scion"
)

type stringVal string

func (v *stringVal) Set(val string) error {
	*v = stringVal(val)
	return nil
}

func (v *stringVal) Type() string   { return "string" }
func (v *stringVal) String() string { return string(*v) }

type iaVal addr.IA

func (v *iaVal) Set(val string) error {
	ia, err := addr.ParseIA(val)
	if err != nil {
		return err
	}
	*v = iaVal(ia)
	return nil
}

func (v *iaVal) Type() string   { return "isd-as" }
func (v *iaVal) String() string { return addr.IA(*v).String() }

type ipVal netip.Addr

func (v *ipVal) Set(val string) error {
	ip, err := netip.ParseAddr(val)
	if err != nil {
		return err
	}
	*v = ipVal(ip)
	return nil
}

func (v *ipVal) Type() string   { return "ip" }
func (v *ipVal) String() string { return netip.Addr(*v).String() }

// SCIONEnvironment can be used to access the common SCION configuration values,
// like the SCION daemon address and the local IP as well as the local ISD-AS.
type SCIONEnvironment struct {
	sciondFlag    *pflag.Flag
	sciondEnv     *string
	ia            addr.IA
	iaFlag        *pflag.Flag
	local         netip.Addr
	localEnv      *netip.Addr
	localFlag     *pflag.Flag
	configDir     string
	configDirFlag *pflag.Flag
	file          env.SCION
	filepath      string

	mtx sync.Mutex
}

// Register registers the command line flags. This should be called when command
// line flags are set up, before any command that accesses the values is called.
// It is safe to not call this at all, which means command line flag values are
// not considered.
func (e *SCIONEnvironment) Register(flagSet *pflag.FlagSet) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	e.iaFlag = flagSet.VarPF((*iaVal)(&e.ia), "isd-as", "",
		"The local ISD-AS to use.")
	e.localFlag = flagSet.VarPF((*ipVal)(&e.local), "local", "l",
		"Local IP address to listen on.")
	sciond := ""
	e.sciondFlag = flagSet.VarPF(
		(*stringVal)(&sciond), "sciond", "",
		`Connect to SCION Daemon at the specified address instead of using
the local topology.json (IP:Port or "default" for `+defaultDaemon+`).
If both --sciond and --config-dir are set, --sciond takes priority.`,
	)

	configDirHelp := `Directory containing topology.json and certs/ for standalone mode.
If both --sciond and --config-dir are set, --sciond takes priority.
`
	if runtime.GOOS == "linux" {
		configDirHelp += `Defaults to ` + defaultConfigDirLinux + ` on Linux.`
	} else {
		configDirHelp += `Required on this platform (no default).`
	}
	e.configDirFlag = flagSet.VarPF(
		(*stringVal)(&e.configDir), "config-dir", "",
		configDirHelp,
	)
}

// Validate checks that the flags are consistent.
// Returns an error if neither --sciond nor --config-dir is set and there's no default
// (i.e., on non-Linux platforms where --config-dir has no default).
func (e *SCIONEnvironment) Validate() error {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	sciondSet := e.sciondFlag != nil && e.sciondFlag.Changed
	configDirSet := e.configDirFlag != nil && e.configDirFlag.Changed

	// If either flag is explicitly set, we're good
	if sciondSet || configDirSet {
		return nil
	}

	// Check if there's a daemon configured via environment
	if e.sciondEnv != nil {
		return nil
	}

	// On Linux, we have a default config directory
	if runtime.GOOS == "linux" {
		return nil
	}

	// On non-Linux platforms with no flags set, we need either --sciond or --config-dir
	return serrors.New("either --sciond or --config-dir must be specified on this platform")
}

// LoadExternalVar loads variables from the SCION environment file and from the
// OS environment variables. Parsing errors will be reported with an error. A
// missing file or environment variable is not reported.
func (e *SCIONEnvironment) LoadExternalVars() error {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	if err := e.loadFile(); err != nil {
		return serrors.Wrap("loading environment file", err)
	}
	if err := e.loadEnv(); err != nil {
		return serrors.Wrap("loading environment variables", err)
	}
	return nil
}

// loadFile loads the environment file. If the file can't be read or parsed an
// error is returned. If the file doesn't exist no error is returned and values
// from the environment file are not considered.
func (e *SCIONEnvironment) loadFile() error {
	if e.filepath == "" {
		e.filepath = defaultEnvironmentFile
	}

	raw, err := os.ReadFile(e.filepath)
	if errors.Is(err, fs.ErrNotExist) {
		// environment file doesn't have to exist.
		return nil
	}
	if err != nil {
		return serrors.Wrap("loading file", err)
	}
	if err := json.Unmarshal(raw, &e.file); err != nil {
		return serrors.Wrap("parsing file", err)
	}
	return nil
}

// loadEnv loads the environment variables. It returns an error if the values
// can't be parsed. Missing variables are not an error. This needs to be called
// before accessing the values, otherwise the environment variables are not
// respected.
func (e *SCIONEnvironment) loadEnv() error {
	if d, ok := os.LookupEnv("SCION_DAEMON"); ok {
		e.sciondEnv = &d
	}
	if l, ok := os.LookupEnv("SCION_LOCAL_ADDR"); ok {
		a, err := netip.ParseAddr(l)
		if err != nil {
			return serrors.Wrap("parsing SCION_LOCAL_ADDR", err)
		}
		e.localEnv = &a
	}
	return nil
}

// Daemon returns the SCION daemon address if explicitly configured.
// Returns empty string if no daemon was configured, allowing the caller
// to fall back to using the local topology.
// The value is loaded from one of the following sources with precedence:
//  1. Command line flag (--sciond)
//  2. Environment variable (SCION_DAEMON)
//  3. Environment configuration file
//
// If none are set, returns empty string (not the default address).
func (e *SCIONEnvironment) Daemon() string {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	if e.sciondFlag != nil && e.sciondFlag.Changed {
		value := e.sciondFlag.Value.String()
		if value == "default" {
			return defaultDaemon
		}
		return value
	}
	if e.sciondEnv != nil {
		return *e.sciondEnv
	}
	ia := e.file.General.DefaultIA
	if e.iaFlag != nil && e.iaFlag.Changed {
		ia = e.ia
	}
	if as, ok := e.file.ASes[ia]; ok && as.DaemonAddress != "" {
		return as.DaemonAddress
	}
	return ""
}

// Local returns the loca IP to listen on. The value is loaded from one of the
// following sources with the precedence as listed:
//  1. Command line flag
//  2. Environment variable
//  3. Default value.
func (e *SCIONEnvironment) Local() netip.Addr {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	if e.localFlag != nil && e.localFlag.Changed {
		return e.local
	}
	if e.localEnv != nil {
		return *e.localEnv
	}
	return netip.Addr{}
}

// ConfigDir returns the configuration directory for standalone mode.
// The value is determined with the following precedence:
//  1. Command line flag (--config-dir)
//  2. On Linux: defaults to /etc/scion
//  3. On other platforms: returns empty string (must be specified via flag)
func (e *SCIONEnvironment) ConfigDir() string {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	if e.configDirFlag != nil && e.configDirFlag.Changed {
		return e.configDir
	}
	// Default to /etc/scion on Linux only
	if runtime.GOOS == "linux" {
		return defaultConfigDirLinux
	}
	return ""
}
