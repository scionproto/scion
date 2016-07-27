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
	"io/ioutil"

	log "github.com/Sirupsen/logrus"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/util"
	"gopkg.in/yaml.v2"
)

type Topo struct {
	BR   map[string]TopoBR    `yaml:"BorderRouters"`
	BS   map[string]BasicElem `yaml:"BeaconServers"`
	PS   map[string]BasicElem `yaml:"PathServers"`
	CS   map[string]BasicElem `yaml:"CertificateServers"`
	SB   map[string]BasicElem `yaml:"SibraServers"`
	ZK   map[int]BasicElem    `yaml:"Zookeepers"`
	Core bool                 `yaml:"Core"`
	IA   addr.ISD_AS          `yaml:"ISD_AS"`
	MTU  int                  `yaml:"MTU"`
}

type BasicElem struct {
	Addr util.YamlIP `yaml:"Addr"`
	Port int         `yaml:"Port"`
}

type TopoBR struct {
	BasicElem `yaml:",inline"`
	IF        TopoIF `yaml:"Interface"`
}

type TopoIF struct {
	Addr      util.YamlIP `yaml:"Addr"`
	UdpPort   int         `yaml:"UdpPort"`
	ToAddr    util.YamlIP `yaml:"ToAddr"`
	ToUdpPort int         `yaml:"ToUdpPort"`
	IFID      int         `yaml:"IFID"`
	IA        addr.ISD_AS `yaml:"ISD_AS"`
	MTU       int         `yaml:"MTU"`
	LinkType  string      `yaml:"LinkType"`
}

var CurrTopo *Topo

func Load(path string) error {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Unable to open topology")
		return err
	}
	if err = Parse(b); err != nil {
		return err
	}
	log.WithField("path", path).Info("Loaded topology")
	return nil
}

func Parse(data []byte) error {
	t := &Topo{}
	if err := yaml.Unmarshal(data, t); err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Unable to parse topology")
		return err
	}
	CurrTopo = t
	return nil
}
