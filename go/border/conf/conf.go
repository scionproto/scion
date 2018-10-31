// Copyright 2016 ETH Zurich
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

// Package conf holds all of the global router state, for access by the
// router's various packages.
package conf

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

// Conf is the main config structure.
type Conf struct {
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
	HFMacPool sync.Pool
	// Net is the network configuration of this router.
	Net *netconf.NetConf
	// Dir is the configuration directory.
	Dir string
}

// Load sets up the configuration, loading it from the supplied config directory.
func Load(id, confDir string) (*Conf, error) {
	conf := &Conf{
		Dir: confDir,
	}
	if err := conf.LoadTopo(id); err != nil {
		return nil, err
	}
	if err := conf.LoadAsConf(); err != nil {
		return nil, err
	}
	if err := conf.LoadMasterKeys(); err != nil {
		return nil, err
	}
	if err := conf.InitMacPool(); err != nil {
		return nil, err
	}
	if err := conf.InitNet(); err != nil {
		return nil, err
	}
	return conf, nil
}

// LoadTopo loads the topology from the config directory and initializes the
// entries related to topo in the config.
func (c *Conf) LoadTopo(id string) error {
	topoPath := filepath.Join(c.Dir, topology.CfgName)
	topo, err := topology.LoadFromFile(topoPath)
	if err != nil {
		return err
	}
	if err := c.InitTopo(id, topo); err != nil {
		return common.NewBasicError("Unable to initialize topo", err, "path", topoPath)
	}
	return nil
}

// InitTopo initializesthe entries related to topo in the config.
func (c *Conf) InitTopo(id string, topo *topology.Topo) error {
	c.Topo = topo
	c.IA = c.Topo.ISD_AS
	// Find the config for this router.
	topoBR, ok := c.Topo.BR[id]
	if !ok {
		return common.NewBasicError("Unable to find element ID in topology", nil,
			"id", id)
	}
	c.BR = &topoBR
	return nil
}

// LoadAsConf loads the as config from the config directory.
func (c *Conf) LoadAsConf() error {
	asConfPath := filepath.Join(c.Dir, as_conf.CfgName)
	if err := as_conf.Load(asConfPath); err != nil {
		return err
	}
	c.ASConf = as_conf.CurrConf
	return nil
}

// LoadMasterKeys loads the master keys from the config directory.
func (c *Conf) LoadMasterKeys() error {
	var err error
	c.MasterKeys, err = keyconf.LoadMaster(filepath.Join(c.Dir, "keys"))
	if err != nil {
		return common.NewBasicError("Unable to load master keys", err)
	}
	return nil
}

// InitMacPool initializes the hop field mac pool.
func (c *Conf) InitMacPool() error {
	// Generate keys
	// This uses 16B keys with 1000 hash iterations, which is the same as the
	// defaults used by pycrypto.
	hfGenKey := pbkdf2.Key(c.MasterKeys.Key0, []byte("Derive OF Key"), 1000, 16, sha256.New)

	// First check for MAC creation errors.
	if _, err := scrypto.InitMac(hfGenKey); err != nil {
		return err
	}
	// Create a pool of MAC instances.
	c.HFMacPool = sync.Pool{
		New: func() interface{} {
			mac, _ := scrypto.InitMac(hfGenKey)
			return mac
		},
	}
	return nil
}

// InitNet initializes the network configuration.
func (c *Conf) InitNet() error {
	var err error
	if c.Net, err = netconf.FromTopo(c.BR.IFIDs, c.Topo.IFInfoMap); err != nil {
		return err
	}
	return nil
}
