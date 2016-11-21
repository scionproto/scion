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
	"crypto/cipher"
	"crypto/sha1"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/pbkdf2"

	"github.com/netsec-ethz/scion/go/border/netconf"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/as_conf"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/topology"
	"github.com/netsec-ethz/scion/go/lib/util"
	"github.com/netsec-ethz/scion/go/proto"
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
	// HFGenBlock is the Hop Field generation block cipher instance.
	HFGenBlock cipher.Block
	// Net is the network configuration of this router.
	Net *netconf.NetConf
	// Dir is the configuration directory.
	Dir string
	// IFStates is a map of interface IDs to interface states, protected by a RWMutex.
	IFStates struct {
		sync.RWMutex
		M map[spath.IntfID]IFState
	}
}

// IFState stores the IFStateInfo capnp message, as well as the raw revocation
// info for a given interface.
type IFState struct {
	P      proto.IFStateInfo
	RawRev common.RawBytes
}

// C is a pointer to the current configuration.
var C *Conf

// Load sets up the configuration, loading it from the supplied config directory.
func Load(id, confDir string) *common.Error {
	var err *common.Error

	// Declare a new Conf instance, and load the topology config.
	conf := &Conf{}
	conf.Dir = confDir
	topoPath := filepath.Join(conf.Dir, topology.CfgName)
	if err = topology.Load(topoPath); err != nil {
		return err
	}
	conf.TopoMeta = topology.Curr
	conf.IA = conf.TopoMeta.T.IA
	// Find the config for this router.
	topoBR, ok := conf.TopoMeta.T.BR[id]
	if !ok {
		return common.NewError("Unable to find element ID in topology", "id", id, "path", topoPath)
	}
	conf.BR = &topoBR
	// Load AS configuration
	asConfPath := filepath.Join(conf.Dir, as_conf.CfgName)
	if err = as_conf.Load(asConfPath); err != nil {
		return err
	}
	conf.ASConf = as_conf.CurrConf

	// Generate keys
	// This uses 16B keys with 1000 hash iterations, which is the same as the
	// defaults used by pycrypto.
	hfGenKey := pbkdf2.Key(conf.ASConf.MasterASKey, []byte("Derive OF Key"), 1000, 16, sha1.New)
	if conf.HFGenBlock, err = util.InitAES(hfGenKey); err != nil {
		return err
	}
	// Create network configuration
	conf.Net = netconf.FromTopo(conf.BR)
	// Save config
	C = conf
	return nil
}
