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
	// TopoMeta contains the names of all local infrastructure elements, a map
	// of interface IDs to routers, and the actual topology.
	TopoMeta *topology.TopoMeta
	// IA is the current ISD-AS.
	IA *addr.ISD_AS
	// BR is the topology information of this router.
	BR *topology.TopoBR
	// ASConf is the local AS configuration.
	ASConf *as_conf.ASConf
	// HFMacPool is the pool of Hop Field MAC generation instances.
	HFMacPool sync.Pool
	// Net is the network configuration of this router.
	Net *netconf.NetConf
	// Dir is the configuration directory.
	Dir string
	// DRKeyPool is the pool of DRKey generation instances.
	DRKeyPool sync.Pool
}

// Load sets up the configuration, loading it from the supplied config directory.
func Load(id, confDir string) (*Conf, *common.Error) {
	var err *common.Error

	// Declare a new Conf instance, and load the topology config.
	conf := &Conf{}
	conf.Dir = confDir
	topoPath := filepath.Join(conf.Dir, topology.CfgName)
	if conf.TopoMeta, err = topology.Load(topoPath); err != nil {
		return nil, err
	}
	conf.IA = conf.TopoMeta.T.IA
	// Find the config for this router.
	topoBR, ok := conf.TopoMeta.T.BR[id]
	if !ok {
		return nil, common.NewError("Unable to find element ID in topology", "id", id, "path", topoPath)
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
	conf.Net = netconf.FromTopo(conf.BR)

	// Create DRKey secret
	drkeySecret := pbkdf2.Key(conf.ASConf.MasterASKey, []byte("Derive DRKey Key"), 1000, 16, sha256.New)
	if _, err = util.InitMac(drkeySecret); err != nil {
		return nil, err
	}
	conf.DRKeyPool = sync.Pool{
		New: func() interface{} {
			mac, _ := util.InitMac(drkeySecret)
			return mac
		},
	}

	// Save config
	return conf, nil
}
