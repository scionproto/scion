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
	"cmp"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/scionproto/scion/testing/clab/cmd/controller/config"
	"github.com/scionproto/scion/testing/clab/cmd/controller/prism"
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

// startOrder ranks the service binaries so dispatchers start before the
// services that register with them; the rest of the order is stable but
// otherwise arbitrary.
var startOrder = map[string]int{
	"dispatcher": 0,
	"router":     1,
	"control":    2,
	"daemon":     3,
}

// renderServices renders the prism configuration into the per-service TOML
// files, writes them into configDir, and returns the services to run with their
// binaries resolved under binDir. The result is deterministically ordered
// (dispatchers first, see startOrder, then by service id) so start order is
// stable.
func renderServices(cfg config.Config, configDir, binDir string) ([]service, error) {
	files, err := prism.Render(cfg)
	if err != nil {
		return nil, fmt.Errorf("rendering service configs: %w", err)
	}
	var services []service
	for _, f := range files {
		path := filepath.Join(configDir, f.Name)
		if err := os.WriteFile(path, f.Content, 0o644); err != nil {
			return nil, fmt.Errorf("writing %q: %w", path, err)
		}
		services = append(services, service{
			name:   strings.TrimSuffix(f.Name, ".toml"),
			binary: filepath.Join(binDir, f.Binary),
			args:   []string{"--config", path},
		})
	}

	slices.SortFunc(services, func(a, b service) int {
		return cmp.Or(
			cmp.Compare(startOrder[filepath.Base(a.binary)], startOrder[filepath.Base(b.binary)]),
			cmp.Compare(a.name, b.name),
		)
	})
	return services, nil
}

// printServices writes the discovered services as an aligned table: the service
// id, the binary that runs it, and the arguments (the config file). The output
// is the static view derived from the prism configuration, the same set the
// supervisor would launch.
func printServices(w io.Writer, services []service) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVICE\tBINARY\tARGS")
	for _, s := range services {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", s.name, s.binary, strings.Join(s.args, " "))
	}
	return tw.Flush()
}
