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

	"github.com/netsec-ethz/scion/go/border/netconf"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/as_conf"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/topology"
	"github.com/netsec-ethz/scion/go/lib/util"
)

// Conf is the main config structure.
type Conf struct {
	// Topo contains the names of all local infrastructure elements, a map
	// of interface IDs to routers, and the actual topology.
	Topo *topology.Topo
	// IA is the current ISD-AS.
	IA *addr.ISD_AS
	// BR is the topology information of this router.
	BR *topology.BRInfo
	// ASConf is the local AS configuration.
	ASConf *as_conf.ASConf
	// HFMacPool is the pool of Hop Field MAC generation instances.
	HFMacPool sync.Pool
	// Net is the network configuration of this router.
	Net *netconf.NetConf
	// Dir is the configuration directory.
	Dir string
}

// Load sets up the configuration, loading it from the supplied config directory.
func Load(id, confDir string) (*Conf, error) {
	var err error

	// Declare a new Conf instance, and load the topology config.
	conf := &Conf{}
	conf.Dir = confDir
	topoPath := filepath.Join(conf.Dir, topology.CfgName)
	if conf.Topo, err = topology.LoadFromFile(topoPath); err != nil {
		return nil, err
	}
	conf.IA = conf.Topo.ISD_AS
	// Find the config for this router.
	topoBR, ok := conf.Topo.BR[id]
	if !ok {
		return nil, common.NewCError("Unable to find element ID in topology",
			"id", id, "path", topoPath)
	}
	conf.BR = &topoBR
	// Load AS configuration
	asConfPath := filepath.Join(conf.Dir, as_conf.CfgName)
	if err = as_conf.Load(asConfPath); err != nil {
		return nil, err
	}
	conf.ASConf = as_conf.CurrConf

	// Generate keys
	// This uses 16B keys with 1000 hash iterations, which is the same as the
	// defaults used by pycrypto.
	hfGenKey := pbkdf2.Key(conf.ASConf.MasterASKey, []byte("Derive OF Key"), 1000, 16, sha256.New)

	// First check for MAC creation errors.
	if _, err = util.InitMac(hfGenKey); err != nil {
		return nil, err
	}
	// Create a pool of MAC instances.
	conf.HFMacPool = sync.Pool{
		New: func() interface{} {
			mac, _ := util.InitMac(hfGenKey)
			return mac
		},
	}

	// Create network configuration
	if conf.Net, err = netconf.FromTopo(conf.BR.IFIDs, conf.Topo.IFInfoMap); err != nil {
		return nil, err
	}
	// Save config
	return conf, nil
}
