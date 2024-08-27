// Copyright 2020 Anapaya Systems
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

package control

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/keyconf"
	"github.com/scionproto/scion/private/topology"
)

// Config stores the runtime configuration state of an ISD-AS context.
type Config struct {
	// Topo contains the names of all local infrastructure elements, a map
	// of interface IDs to routers, and the actual topology.
	Topo topology.Topology
	// IA is the current ISD-AS.
	IA addr.IA
	// BR is the topology information of this router.
	BR *topology.BRInfo
	// MasterKeys holds the local AS master keys.
	MasterKeys keyconf.Master
}

// LoadConfig sets up the configuration, loading it from the supplied config directory.
func LoadConfig(id, confDir string) (*Config, error) {
	conf := &Config{}
	if err := conf.loadTopo(id, confDir); err != nil {
		return nil, err
	}
	if err := conf.loadMasterKeys(confDir); err != nil {
		return nil, err
	}
	return conf, nil
}

func (cfg *Config) String() string {
	return fmt.Sprintf("{IA: %s, BR.Name: %s", cfg.IA, cfg.BR.Name)
}

// loadTopo loads the topology from the config directory and initializes the
// entries related to topo in the config.
func (cfg *Config) loadTopo(id string, confDir string) error {
	topoPath := filepath.Join(confDir, "topology.json")
	topo, err := topology.FromJSONFile(topoPath)
	if err != nil {
		return err
	}
	if err := cfg.initTopo(id, topo); err != nil {
		return serrors.Wrap("initializing topology", err, "file", topoPath)
	}
	return nil
}

// initTopo initializes the entries related to topo in the config.
func (cfg *Config) initTopo(id string, topo topology.Topology) error {
	cfg.Topo = topo
	cfg.IA = cfg.Topo.IA()
	// Find the config for this router.
	topoBR, ok := cfg.Topo.BR(id)
	if !ok {
		return serrors.New("element ID not found", "id", id)
	}
	cfg.BR = &topoBR
	return nil
}

// loadMasterKeys loads the master keys from the config directory.
func (cfg *Config) loadMasterKeys(confDir string) error {
	var err error
	cfg.MasterKeys, err = keyconf.LoadMaster(filepath.Join(confDir, "keys"))
	if err != nil {
		return serrors.Wrap("loading master keys", err)
	}
	return nil
}

// IACtx is the context for the router for a given IA.
type IACtx struct {
	// Config is the router topology configuration
	Config *Config
	// DP is the underlying data plane.
	DP Dataplane
}

// Configure configures the dataplane for the given context.
func (iac *IACtx) Configure() error {
	cfg := iac.Config
	if cfg == nil {
		// Nothing to do
		return serrors.New("empty configuration")
	}

	log.Debug("Configuring Dataplane")
	if err := ConfigDataplane(iac.DP, cfg); err != nil {
		brConfDump, errDump := dumpConfig(cfg)
		if errDump != nil {
			brConfDump = errDump.Error()
		}
		return serrors.Wrap("config setup", err, "config", brConfDump)
	}
	log.Debug("Dataplane configured successfully", "config", cfg)
	return nil
}

func dumpConfig(cfg *Config) (string, error) {
	if cfg == nil {
		return "", serrors.New("empty configuration")
	}
	b, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
