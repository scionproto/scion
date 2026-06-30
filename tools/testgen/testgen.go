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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

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
	// LabName is the containerlab lab name.
	LabName string
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
		LabName:    "scion",
	}
}

// Run executes the full pipeline.
func Run(cfg Config) error {
	w := cfg.Writer
	if w == nil {
		w = io.Discard
	}

	if _, err := os.Stat(cfg.OutDir); err == nil {
		if err := os.RemoveAll(cfg.OutDir); err != nil {
			return serrors.Wrap("removing output directory", err)
		}
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
	if err := writeIntegrationMetadata(network, dir); err != nil {
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
	if err := generateMasterKeys(network, dir); err != nil {
		return serrors.Wrap("generating master keys", err)
	}

	// Phase 6: clab.
	labName := cfg.LabName
	if labName == "" {
		labName = "scion"
	}
	if err := clab.Generate(network, dir, clab.Options{
		LabName: labName,
		MgmtV4:  mgmtV4(cfg.NetworkV4),
		MgmtV6:  mgmtV6(cfg.NetworkV6),
	}, w); err != nil {
		return err
	}

	// Phase 7: instructions (no-op for MVP).
	if err := instructions.Write(dir, w); err != nil {
		return err
	}

	fmt.Fprintf(w, "done: output written to %s\n", dir.Base())
	return nil
}

// writeIntegrationMetadata writes the gen-root files the integration framework
// (tools/integration) consumes: as_list.yml (core/non-core grouping) and
// sciond_addresses.json (ISD-AS -> daemon IP; the framework appends the daemon
// API port). The daemon of each AS is reachable from the host over the
// containerlab management network.
func writeIntegrationMetadata(network *hydrate.Network, dir out.Dir) error {
	type asList struct {
		Core    []string `yaml:"Core"`
		NonCore []string `yaml:"Non-core"`
	}
	var list asList
	sciond := map[string]string{}
	for _, as := range network.ASes {
		ia := as.IA.String()
		if as.Attrs.Core {
			list.Core = append(list.Core, ia)
		} else {
			list.NonCore = append(list.NonCore, ia)
		}
		sciond[ia] = as.Daemon.Addr.Addr().String()
	}

	listRaw, err := yaml.Marshal(list)
	if err != nil {
		return serrors.Wrap("marshaling as_list.yml", err)
	}
	if err := out.WriteFile(filepath.Join(dir.Base(), "as_list.yml"), listRaw); err != nil {
		return err
	}
	sciondRaw, err := json.MarshalIndent(sciond, "", "  ")
	if err != nil {
		return serrors.Wrap("marshaling sciond_addresses.json", err)
	}
	return out.WriteFile(filepath.Join(dir.Base(), "sciond_addresses.json"), sciondRaw)
}

// generateMasterKeys writes the per-AS master secrets (master0.key,
// master1.key) into each AS's keys directory. They are base64-encoded 16-byte
// random values, shared by all the AS's hosts (border routers derive hop-field
// MAC keys from them, the control service derives DRKey secrets).
func generateMasterKeys(network *hydrate.Network, dir out.Dir) error {
	for _, as := range network.ASes {
		keysDir := filepath.Join(dir.AS(as.IA), "keys")
		for _, name := range []string{"master0.key", "master1.key"} {
			buf := make([]byte, 16)
			if _, err := rand.Read(buf); err != nil {
				return serrors.Wrap("reading random bytes", err)
			}
			enc := base64.StdEncoding.EncodeToString(buf)
			if err := out.WriteFile(filepath.Join(keysDir, name), []byte(enc)); err != nil {
				return err
			}
		}
	}
	return nil
}

// mgmtV4 returns the management subnet for the clab nodes: the /16 region of
// the allocator base network that holds the AS-internal /24s. Returns the zero
// value if base is unset.
func mgmtV4(base netip.Prefix) netip.Prefix {
	if !base.IsValid() {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(base.Addr(), 16).Masked()
}

// mgmtV6 returns the IPv6 management subnet for the clab nodes: the base /64 of
// the allocator network, which holds every AS's host addresses. It is a /64
// (not the wider base) because docker's IPv6 IPAM only tracks a network's base
// /64; handing it a wider subnet makes per-host static addresses collide.
// Returns the zero value if base is unset.
func mgmtV6(base netip.Prefix) netip.Prefix {
	if !base.IsValid() {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(base.Addr(), 64).Masked()
}

// generateConfigs writes, for each AS, the shared topology.json, and for each
// host the generalized config and the rendered service files.
func generateConfigs(network *hydrate.Network, dir out.Dir) error {
	for _, as := range network.ASes {
		topoRaw, err := json.MarshalIndent(config.Topology(as), "", "  ")
		if err != nil {
			return serrors.Wrap("marshaling topology.json", err, "as", as.IA)
		}
		// A per-AS copy at the AS directory root is what the integration
		// framework's CSAddr lookup reads (gen/AS<...>/topology.json).
		if err := out.WriteFile(filepath.Join(dir.AS(as.IA), "topology.json"), topoRaw); err != nil {
			return err
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
				// tools/await-connectivity reads the control service config at
				// the AS-directory root (gen/AS<...>/cs*.toml) to find the CS
				// API address; mirror it there.
				if strings.HasPrefix(f.Name, "cs") {
					if err := out.WriteFile(filepath.Join(dir.AS(as.IA), f.Name), f.Content); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
