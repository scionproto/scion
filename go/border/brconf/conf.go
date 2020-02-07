// Copyright 2016 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

// Package brconf holds all of the global router state, for access by the
// router's various packages.
package brconf

import (
	"path/filepath"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/topology"
)

// BRConf is the main config structure. It contains the dynamic
// configuration at runtime.
type BRConf struct {
	// Topo contains the names of all local infrastructure elements, a map
	// of interface IDs to routers, and the actual topology.
	Topo topology.Topology
	// IA is the current ISD-AS.
	IA addr.IA
	// BR is the topology information of this router.
	BR *topology.BRInfo
	// MasterKeys holds the local AS master keys.
	MasterKeys keyconf.Master
	// Dir is the configuration directory.
	Dir string
}

// Load sets up the configuration, loading it from the supplied config directory.
func Load(id, confDir string) (*BRConf, error) {
	conf := &BRConf{
		Dir: confDir,
	}
	if err := conf.loadTopo(id); err != nil {
		return nil, err
	}
	if err := conf.loadMasterKeys(); err != nil {
		return nil, err
	}
	return conf, nil
}

// WithNewTopo creates config that shares all content except fields related
// to topology with the oldConf.
func WithNewTopo(id string, topo topology.Topology, oldConf *BRConf) (*BRConf, error) {
	conf := &BRConf{
		Dir:        oldConf.Dir,
		MasterKeys: oldConf.MasterKeys,
	}
	if err := conf.initTopo(id, topo); err != nil {
		return nil, common.NewBasicError("Unable to initialize topo", err)
	}
	return conf, nil
}

// loadTopo loads the topology from the config directory and initializes the
// entries related to topo in the config.
func (cfg *BRConf) loadTopo(id string) error {
	topoPath := filepath.Join(cfg.Dir, "topology.json")
	topo, err := topology.FromJSONFile(topoPath)
	if err != nil {
		return err
	}
	if err := cfg.initTopo(id, topo); err != nil {
		return common.NewBasicError("Unable to initialize topo", err, "path", topoPath)
	}
	return nil
}

// initTopo initializes the entries related to topo in the config.
func (cfg *BRConf) initTopo(id string, topo topology.Topology) error {
	cfg.Topo = topo
	cfg.IA = cfg.Topo.IA()
	// Find the config for this router.
	topoBR, ok := cfg.Topo.BR(id)
	if !ok {
		return common.NewBasicError("Unable to find element ID in topology", nil,
			"id", id)
	}
	cfg.BR = &topoBR
	return nil
}

// loadMasterKeys loads the master keys from the config directory.
func (cfg *BRConf) loadMasterKeys() error {
	var err error
	cfg.MasterKeys, err = keyconf.LoadMaster(filepath.Join(cfg.Dir, "keys"))
	if err != nil {
		return common.NewBasicError("Unable to load master keys", err)
	}
	return nil
}
