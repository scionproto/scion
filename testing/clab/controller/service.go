// Copyright 2026 Anapaya Systems
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

package main

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
)

// service is a single SCION process the controller supervises.
type service struct {
	// name is the log name; it is the config-file stem (the service id).
	name string
	// binary is the absolute path of the executable to run.
	binary string
	// args is the full argument vector passed to the binary.
	args []string
}

// serviceKind ties a SCION service binary to the config-file glob that
// topogen emits for it. For each config file the controller launches
// "<binDir>/<binary> --config <configDir>/<file>".
type serviceKind struct {
	binary string
	glob   string
}

// knownKinds enumerates the services the controller manages, matching the
// file-naming convention produced by topogen (tools/topology). A node may run
// several dispatchers (one per service that needs local UDP forwarding),
// several routers, and several control services; the daemon is a single
// instance per AS.
//
// Order matters: it is the start order. Dispatchers come first so their
// forwarding sockets are up before the services that register with them.
var knownKinds = []serviceKind{
	{binary: "dispatcher", glob: "disp_*.toml"},
	{binary: "router", glob: "br*.toml"},
	{binary: "control", glob: "cs*.toml"},
	{binary: "daemon", glob: "sd.toml"},
}

// discover scans configDir for the per-service TOML files produced by topogen
// and returns the services to run, with their binaries resolved under binDir.
// The result is deterministically ordered (kind order, then filename).
func discover(configDir, binDir string) ([]service, error) {
	var services []service
	for _, k := range knownKinds {
		matches, err := filepath.Glob(filepath.Join(configDir, k.glob))
		if err != nil {
			// The only possible error is ErrBadPattern, which is a bug here.
			return nil, fmt.Errorf("globbing %q: %w", k.glob, err)
		}
		sort.Strings(matches)
		for _, cfg := range matches {
			name := strings.TrimSuffix(filepath.Base(cfg), ".toml")
			services = append(services, service{
				name:   name,
				binary: filepath.Join(binDir, k.binary),
				args:   []string{"--config", cfg},
			})
		}
	}
	return services, nil
}

// printServices writes the discovered services as an aligned table: the service
// id, the binary that runs it, and the arguments (the config file). The output
// is the static view derived from the config directory, the same set the
// supervisor would launch.
func printServices(w io.Writer, services []service) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVICE\tBINARY\tARGS")
	for _, s := range services {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", s.name, s.binary, strings.Join(s.args, " "))
	}
	return tw.Flush()
}
