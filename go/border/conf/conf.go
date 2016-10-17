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

type Conf struct {
	TopoMeta   *topology.TopoMeta
	IA         *addr.ISD_AS
	BR         *topology.TopoBR
	AS         *as_conf.ASConf
	HFGenBlock cipher.Block
	Net        *netconf.NetConf
	Dir        string
	IFStates   struct {
		sync.RWMutex
		M map[spath.IntfID]IFState
	}
}

type IFState struct {
	P      proto.IFStateInfo
	RawRev common.RawBytes
}

var C *Conf

func Load(id, confDir string) *common.Error {
	var err *common.Error

	conf := &Conf{}
	conf.Dir = confDir
	topoPath := filepath.Join(conf.Dir, topology.CfgName)
	if err = topology.Load(topoPath); err != nil {
		return err
	}
	conf.TopoMeta = topology.Curr
	conf.IA = conf.TopoMeta.T.IA

	topoBR, ok := conf.TopoMeta.T.BR[id]
	if !ok {
		return common.NewError("Unable to find element ID in topology", "id", id, "path", topoPath)
	}
	conf.BR = &topoBR

	asConfPath := filepath.Join(conf.Dir, as_conf.CfgName)
	if err = as_conf.Load(asConfPath); err != nil {
		return err
	}
	conf.AS = as_conf.CurrConf

	// Generate key of length 16 with 1000 hash iterations, which is the same as
	// the defaults used by pycrypto.
	hfGenKey := pbkdf2.Key(conf.AS.MasterASKey, []byte("Derive OF Key"), 1000, 16, sha1.New)
	if conf.HFGenBlock, err = util.InitAES(hfGenKey); err != nil {
		return err
	}

	conf.Net = netconf.FromTopo(conf.BR)
	C = conf
	return nil
}
