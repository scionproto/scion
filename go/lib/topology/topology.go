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

package topology

import (
	"fmt"
	"io/ioutil"
	"sort"

	"gopkg.in/yaml.v2"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/util"
)

type TopoMeta struct {
	T       Topo
	BRNames []string
	BSNames []string
	PSNames []string
	CSNames []string
	SBNames []string
	ZKIDs   []int
	IFMap   map[int]TopoBR
}

type Topo struct {
	BR   map[string]TopoBR    `yaml:"BorderRouters"`
	BS   map[string]BasicElem `yaml:"BeaconServers"`
	PS   map[string]BasicElem `yaml:"PathServers"`
	CS   map[string]BasicElem `yaml:"CertificateServers"`
	SB   map[string]BasicElem `yaml:"SibraServers"`
	ZK   map[int]BasicElem    `yaml:"Zookeepers"`
	Core bool                 `yaml:"Core"`
	IA   *addr.ISD_AS         `yaml:"ISD_AS"`
	MTU  int                  `yaml:"MTU"`
}

type BasicElem struct {
	Addr *util.YamlIP `yaml:"Addr"`
	Port int          `yaml:"Port"`
}

func (b BasicElem) String() string {
	return fmt.Sprintf("%s:%d", b.Addr, b.Port)
}

type TopoBR struct {
	BasicElem `yaml:",inline"`
	IF        *TopoIF `yaml:"Interface"`
}

func (t TopoBR) String() string {
	return fmt.Sprintf("Loc addrs:\n  %s\nInterfaces:\n  %s", t.BasicElem, t.IF)
}

type TopoIF struct {
	Addr      *util.YamlIP `yaml:"Addr"`
	UdpPort   int          `yaml:"UdpPort"`
	ToAddr    *util.YamlIP `yaml:"ToAddr"`
	ToUdpPort int          `yaml:"ToUdpPort"`
	IFID      int          `yaml:"IFID"`
	IA        *addr.ISD_AS `yaml:"ISD_AS"`
	MTU       int          `yaml:"MTU"`
	BW        int          `yaml:"Bandwidth"`
	LinkType  string       `yaml:"LinkType"`
}

func (t *TopoIF) String() string {
	return fmt.Sprintf(
		"IFID: %d Link: %s Local: %s:%d Remote: %s:%d IA: %s MTU: %d BW: %d",
		t.IFID, t.LinkType, t.Addr, t.UdpPort, t.ToAddr, t.ToUdpPort, t.IA, t.MTU, t.BW,
	)

}

const CfgName = "topology.yml"

const (
	ErrorOpen  = "Unable to open topology"
	ErrorParse = "Unable to parse topology"
)

const (
	LinkRouting = "ROUTING"
	LinkParent  = "PARENT"
	LinkChild   = "CHILD"
	LinkPeer    = "PEER"
)

var Curr *TopoMeta

func Load(path string) *common.Error {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return common.NewError(ErrorOpen, "err", err)
	}
	if err := Parse(b, path); err != nil {
		return err
	}
	return nil
}

func Parse(data []byte, path string) *common.Error {
	tm := &TopoMeta{}
	tm.IFMap = make(map[int]TopoBR)
	if err := yaml.Unmarshal(data, &tm.T); err != nil {
		return common.NewError(ErrorParse, "err", err, "path", path)
	}
	tm.populateMeta()
	Curr = tm
	return nil
}

func (tm *TopoMeta) populateMeta() {
	for k, v := range tm.T.BR {
		tm.BRNames = append(tm.BRNames, k)
		tm.IFMap[v.IF.IFID] = v
	}
	for k := range tm.T.BS {
		tm.BSNames = append(tm.BSNames, k)
	}
	for k := range tm.T.PS {
		tm.PSNames = append(tm.PSNames, k)
	}
	for k := range tm.T.CS {
		tm.CSNames = append(tm.CSNames, k)
	}
	for k := range tm.T.SB {
		tm.SBNames = append(tm.SBNames, k)
	}
	for k := range tm.T.ZK {
		tm.ZKIDs = append(tm.ZKIDs, k)
	}
	sort.Strings(tm.BRNames)
	sort.Strings(tm.BSNames)
	sort.Strings(tm.PSNames)
	sort.Strings(tm.CSNames)
	sort.Strings(tm.SBNames)
	sort.Ints(tm.ZKIDs)
}
