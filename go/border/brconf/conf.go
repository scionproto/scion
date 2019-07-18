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
	"crypto/sha256"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/go/border/netconf"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/as_conf"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/topology"
)

// BRConf is the main config structure. It contains the dynamic
// configuration at runtime.
type BRConf struct {
	// Topo contains the names of all local infrastructure elements, a map
	// of interface IDs to routers, and the actual topology.
	Topo *topology.Topo
	// IA is the current ISD-AS.
	IA addr.IA
	// BR is the topology information of this router.
	BR *topology.BRInfo
	// ASConf is the local AS configuration.
	ASConf *as_conf.ASConf
	// MasterKeys holds the local AS master keys.
	MasterKeys keyconf.Master
	// HFMacPool is the pool of Hop Field MAC generation instances.
	HFMacPool *sync.Pool
	// Net is the network configuration of this router.
	Net *netconf.NetConf
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
	if err := conf.loadAsConf(); err != nil {
		return nil, err
	}
	if err := conf.loadMasterKeys(); err != nil {
		return nil, err
	}
	if err := conf.initMacPool(); err != nil {
		return nil, err
	}
	if err := conf.initNet(); err != nil {
		return nil, err
	}
	return conf, nil
}

// WithNewTopo creates config that shares all content except fields related
// to topology with the oldConf.
func WithNewTopo(id string, topo *topology.Topo, oldConf *BRConf) (*BRConf, error) {
	conf := &BRConf{
		Dir:        oldConf.Dir,
		ASConf:     oldConf.ASConf,
		MasterKeys: oldConf.MasterKeys,
		HFMacPool:  oldConf.HFMacPool,
	}
	if err := conf.initTopo(id, topo); err != nil {
		return nil, common.NewBasicError("Unable to initialize topo", err)
	}
	if err := conf.initNet(); err != nil {
		return nil, common.NewBasicError("Unable to initialize net", err)
	}
	return conf, nil
}

// loadTopo loads the topology from the config directory and initializes the
// entries related to topo in the config.
func (cfg *BRConf) loadTopo(id string) error {
	topoPath := filepath.Join(cfg.Dir, topology.CfgName)
	topo, err := topology.LoadFromFile(topoPath)
	if err != nil {
		return err
	}
	if err := cfg.initTopo(id, topo); err != nil {
		return common.NewBasicError("Unable to initialize topo", err, "path", topoPath)
	}
	return nil
}

// initTopo initializesthe entries related to topo in the config.
func (cfg *BRConf) initTopo(id string, topo *topology.Topo) error {
	cfg.Topo = topo
	cfg.IA = cfg.Topo.ISD_AS
	// Find the config for this router.
	topoBR, ok := cfg.Topo.BR[id]
	if !ok {
		return common.NewBasicError("Unable to find element ID in topology", nil,
			"id", id)
	}
	cfg.BR = &topoBR
	return nil
}

// loadAsConf loads the as config from the config directory.
func (cfg *BRConf) loadAsConf() error {
	asConfPath := filepath.Join(cfg.Dir, as_conf.CfgName)
	if err := as_conf.Load(asConfPath); err != nil {
		return err
	}
	cfg.ASConf = as_conf.CurrConf
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

// initMacPool initializes the hop field mac pool.
func (cfg *BRConf) initMacPool() error {
	// Generate keys
	// This uses 16B keys with 1000 hash iterations, which is the same as the
	// defaults used by pycrypto.
	hfGenKey := pbkdf2.Key(cfg.MasterKeys.Key0, []byte("Derive OF Key"), 1000, 16, sha256.New)

	// First check for MAC creation errors.
	if _, err := scrypto.InitMac(hfGenKey); err != nil {
		return err
	}
	// Create a pool of MAC instances.
	cfg.HFMacPool = &sync.Pool{
		New: func() interface{} {
			mac, _ := scrypto.InitMac(hfGenKey)
			return mac
		},
	}
	return nil
}

// initNet initializes the network configuration.
func (cfg *BRConf) initNet() error {
	var err error
	if cfg.Net, err = netconf.FromTopo(cfg.BR, cfg.Topo.IFInfoMap); err != nil {
		return err
	}
	return nil
}
