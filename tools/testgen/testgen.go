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

// Package testgen runs the topology generation pipeline: parse, hydrate,
// config, service-config, crypto, clab and instructions.
package testgen

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/scionproto/scion/pkg/prism"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/scion-pki/testcrypto"
	"github.com/scionproto/scion/tools/testgen/clab"
	"github.com/scionproto/scion/tools/testgen/config"
	"github.com/scionproto/scion/tools/testgen/hydrate"
	"github.com/scionproto/scion/tools/testgen/instructions"
	"github.com/scionproto/scion/tools/testgen/out"
	"github.com/scionproto/scion/tools/testgen/topo"
)

// Config configures a pipeline run.
type Config struct {
	// TopoFile is the input topology description file.
	TopoFile string
	// OutDir is the output directory.
	OutDir string
	// NetworkV4 and NetworkV6 are the base networks for the default allocator.
	NetworkV4 netip.Prefix
	NetworkV6 netip.Prefix
	// ASValidity is the validity period of generated AS certificates.
	ASValidity time.Duration
	// ISDDir groups ASes under per-ISD directories.
	ISDDir bool
	// Writer receives progress output.
	Writer io.Writer
}

// DefaultConfig returns a Config with the default allocator networks and AS
// certificate validity. The TopoFile and OutDir must still be set.
func DefaultConfig() Config {
	def := hydrate.DefaultClabConfig()
	return Config{
		OutDir:     "gen",
		NetworkV4:  def.NetworkV4,
		NetworkV6:  def.NetworkV6,
		ASValidity: 365 * 24 * time.Hour,
	}
}

// Run executes the full pipeline.
func Run(cfg Config) error {
	w := cfg.Writer
	if w == nil {
		w = io.Discard
	}

	// Phase 1: parse + validate.
	fmt.Fprintf(w, "parse: reading %s\n", cfg.TopoFile)
	t, err := topo.ParseFile(cfg.TopoFile)
	if err != nil {
		return err
	}
	if err := t.Validate(); err != nil {
		return serrors.Wrap("validating topology", err)
	}

	// Phase 2: hydrate.
	fmt.Fprintln(w, "hydrate: allocating subnets and addresses")
	alloc := hydrate.NewClabAllocator(t, hydrate.ClabConfig{
		NetworkV4: cfg.NetworkV4,
		NetworkV6: cfg.NetworkV6,
	})
	network, err := hydrate.Hydrate(t, alloc)
	if err != nil {
		return serrors.Wrap("hydrating topology", err)
	}
	dir := out.New(cfg.OutDir, cfg.ISDDir)
	allocRaw, err := network.Allocations().Marshal()
	if err != nil {
		return err
	}
	if err := out.WriteFile(dir.NetworkAllocations(), allocRaw); err != nil {
		return err
	}

	// Phases 3 + 4: generalized config, topology.json and service files.
	fmt.Fprintln(w, "config: generating per-host configuration and service files")
	if err := generateConfigs(network, dir); err != nil {
		return err
	}

	// Phase 5: crypto.
	fmt.Fprintln(w, "crypto: generating TRCs and certificates")
	if err := testcrypto.Run(testcrypto.Options{
		TopoFile:   cfg.TopoFile,
		OutDir:     dir.Base(),
		ISDDir:     cfg.ISDDir,
		ASValidity: cfg.ASValidity,
		Writer:     w,
	}); err != nil {
		return serrors.Wrap("generating crypto", err)
	}

	// Phase 6: clab (no-op for MVP).
	if err := clab.Generate(network, dir, w); err != nil {
		return err
	}

	// Phase 7: instructions (no-op for MVP).
	if err := instructions.Write(dir, w); err != nil {
		return err
	}

	fmt.Fprintf(w, "done: output written to %s\n", dir.Base())
	return nil
}

// generateConfigs writes, for each AS, the shared topology.json, and for each
// host the generalized config and the rendered service files.
func generateConfigs(network *hydrate.Network, dir out.Dir) error {
	for _, as := range network.ASes {
		topoRaw, err := json.MarshalIndent(config.Topology(as), "", "  ")
		if err != nil {
			return serrors.Wrap("marshaling topology.json", err, "as", as.IA)
		}
		for _, host := range as.Hosts {
			hostDir := dir.Host(as.IA, host.Name)
			cfg := config.HostConfig(as, host)

			cfgRaw, err := cfg.EncodeYAML()
			if err != nil {
				return serrors.Wrap("encoding host config", err, "host", host.Name)
			}
			if err := out.WriteFile(filepath.Join(hostDir, "config.yml"), cfgRaw); err != nil {
				return err
			}
			if err := out.WriteFile(filepath.Join(hostDir, "topology.json"), topoRaw); err != nil {
				return err
			}
			files, err := prism.Render(cfg)
			if err != nil {
				return serrors.Wrap("rendering service files", err, "host", host.Name)
			}
			for _, f := range files {
				if err := out.WriteFile(filepath.Join(hostDir, f.Name), f.Content); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
