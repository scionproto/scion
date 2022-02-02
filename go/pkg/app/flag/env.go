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
	"os"
	"sync"

	"github.com/spf13/pflag"
	"inet.af/netaddr"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/pkg/app/env"
)

const (
	defaultDaemon     = daemon.DefaultAPIAddress
	defaultDispatcher = reliable.DefaultDispPath

	defaultEnvironmentFile = "/etc/scion/environment.json"
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

type ipVal netaddr.IP

func (v *ipVal) Set(val string) error {
	ip, err := netaddr.ParseIP(val)
	if err != nil {
		return err
	}
	*v = ipVal(ip)
	return nil
}

func (v *ipVal) Type() string   { return "ip" }
func (v *ipVal) String() string { return netaddr.IP(*v).String() }

// SCIONEnvironment can be used to access the common SCION configuration values,
// like the SCION daemon address, the dispatcher socket address and the local IP
// as well as the local ISD-AS.
type SCIONEnvironment struct {
	sciondFlag *pflag.Flag
	sciondEnv  *string
	ia         addr.IA
	iaFlag     *pflag.Flag
	dispFlag   *pflag.Flag
	dispEnv    *string
	local      netaddr.IP
	localEnv   *netaddr.IP
	localFlag  *pflag.Flag
	file       env.SCION
	filepath   string

	mtx sync.Mutex
}

// Register registers the command line flags. This should be called when command
// line flags are set up, before any command that accesses the values is called.
// It is safe to not call this at all, which means command line flag values are
// not considered.
func (e *SCIONEnvironment) Register(flagSet *pflag.FlagSet) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	sciond := defaultDaemon
	dispatcher := defaultDispatcher
	e.sciondFlag = flagSet.VarPF((*stringVal)(&sciond), "sciond", "",
		"SCION Deamon address.")
	e.iaFlag = flagSet.VarPF((*iaVal)(&e.ia), "isd-as", "",
		"The local ISD-AS to use.")
	e.dispFlag = flagSet.VarPF((*stringVal)(&dispatcher), "dispatcher", "",
		"Path to the dispatcher socket")
	e.localFlag = flagSet.VarPF((*ipVal)(&e.local), "local", "l",
		"Local IP address to listen on.")
}

// LoadExternalVar loads variables from the SCION environment file and from the
// OS environment variables. Parsing errors will be reported with an error. A
// missing file or environment variable is not reported.
func (e *SCIONEnvironment) LoadExternalVars() error {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	if err := e.loadFile(); err != nil {
		return serrors.WrapStr("loading environment file", err)
	}
	if err := e.loadEnv(); err != nil {
		return serrors.WrapStr("loading environment variables", err)
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
		return serrors.WrapStr("loading file", err)
	}
	if err := json.Unmarshal(raw, &e.file); err != nil {
		return serrors.WrapStr("parsing file", err)
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
	if d, ok := os.LookupEnv("SCION_DISPATCHER"); ok {
		e.dispEnv = &d
	}
	if l, ok := os.LookupEnv("SCION_LOCAL_ADDR"); ok {
		a, err := netaddr.ParseIP(l)
		if err != nil {
			return serrors.WrapStr("parsing SCION_LOCAL_ADDR", err)
		}
		e.localEnv = &a
	}
	return nil
}

// Daemon returns the path to the SCION daemon. The value is loaded from one of
// the following sources with the precedence as listed:
//  1. Command line flag
//  2. Environment variable
//  3. Environment configuration file
//  4. Default value.
func (e *SCIONEnvironment) Daemon() string {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	if e.sciondFlag != nil && e.sciondFlag.Changed {
		return e.sciondFlag.Value.String()
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
	return defaultDaemon
}

// Dispatcher returns the path to the SCION dispatcher socket. The value is
// loaded from one of the following sources with the precedence as listed:
//  1. Command line flag
//  2. Environment variable
//  3. Environment configuration file
//  4. Default value.
func (e *SCIONEnvironment) Dispatcher() string {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	if e.dispFlag != nil && e.dispFlag.Changed {
		return e.dispFlag.Value.String()
	}
	if e.dispEnv != nil {
		return *e.dispEnv
	}
	if s := e.file.General.DispatcherSocket; s != "" {
		return s
	}
	return defaultDispatcher
}

// Local returns the loca IP to listen on. The value is loaded from one of the
// following sources with the precedence as listed:
//  1. Command line flag
//  2. Environment variable
//  3. Default value.
func (e *SCIONEnvironment) Local() netaddr.IP {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	if e.localFlag != nil && e.localFlag.Changed {
		return e.local
	}
	if e.localEnv != nil {
		return *e.localEnv
	}
	return netaddr.IP{}
}
