// Copyright 2018 ETH Zurich
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

package conf

import (
	"path/filepath"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/trust"
)

const (
	ErrorTopo    = "Unable to load topology"
	ErrorAddr    = "Unable to load addresses"
	ErrorKeyConf = "Unable to load KeyConf"
)

type Conf struct {
	// Topo contains the names of all local infrastructure elements, a map
	// of interface IDs to routers, and the actual topology.
	Topo *topology.Topo
	// BindAddr is the local bind address.
	BindAddr *snet.Addr
	// PublicAddr is the public address.
	PublicAddr *snet.Addr
	// KeyConf contains the AS level keys used for signing and decrypting.
	KeyConf *trust.KeyConf
	// Dir is the configuration directory.
	Dir string
}

// Load initializes the configuration by loading it from confDir.
func Load(id string, confDir string) (*Conf, error) {
	var err error
	conf := &Conf{Dir: confDir}
	// load topology
	path := filepath.Join(confDir, topology.CfgName)
	if conf.Topo, err = topology.LoadFromFile(path); err != nil {
		return nil, common.NewBasicError(ErrorTopo, err)
	}
	// load public and bind address
	topoAddr, ok := conf.Topo.CS[id]
	if !ok {
		return nil, common.NewBasicError(ErrorAddr, nil, "err", "Element ID not found",
			"id", id)
	}
	publicInfo := topoAddr.PublicAddrInfo(conf.Topo.Overlay)
	conf.PublicAddr = &snet.Addr{IA: conf.Topo.ISD_AS, Host: addr.HostFromIP(publicInfo.IP),
		L4Port: uint16(publicInfo.L4Port)}
	bindInfo := topoAddr.BindAddrInfo(conf.Topo.Overlay)
	tmpBind := &snet.Addr{IA: conf.Topo.ISD_AS, Host: addr.HostFromIP(bindInfo.IP),
		L4Port: uint16(bindInfo.L4Port)}
	if !tmpBind.EqAddr(conf.PublicAddr) {
		conf.BindAddr = tmpBind
	}
	// load keyConf
	path = filepath.Join(confDir, "keys")
	if conf.KeyConf, err = trust.LoadKeyConf(path, conf.Topo.Core); err != nil {
		return nil, common.NewBasicError(ErrorKeyConf, err)
	}
	return conf, nil
}
