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

// This file handles the loading, parsing and set up of the bandwidth
// enforcement mechanism.

package enforcement

import (
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"

	log "github.com/inconshreveable/log15"

	"io/ioutil"

	"gopkg.in/yaml.v2"
)

const (
	ErrorOpen  = "Unable to open bandwidth enforcement configuration"
	ErrorParse = "Unable to parse bandwidth enforcement configuration"
	CfgName    = "bw.yml"
	unknown    = "unknown"
)

type IfConfig struct {
	Ifid     common.IFIDType
	MaxICapa int64
	MaxECapa int64
	Ingress  map[string]int64
	Egress   map[string]int64
}

type IfConfigs struct {
	Interfaces []IfConfig `yaml:"interfaces"`
}

// Load reads the bandwidth configuration file from the file system.
func Load(path string) (map[common.IFIDType]IFEContainer, map[common.IFIDType]IFEContainer, error) {
	source, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, nil, common.NewCError(ErrorOpen, "err", err)
	}
	ingress, egress, parse_err := Parse(source, path)

	if parse_err != nil {
		return nil, nil, parse_err
	}

	return ingress, egress, nil
}

// Parse() tries to parse the bandwidth configuration file.
func Parse(data []byte, path string) (map[common.IFIDType]IFEContainer, map[common.IFIDType]IFEContainer, error) {
	interfaces := &IfConfigs{}
	if len(data) == 0 {
		return nil, nil, common.NewCError(ErrorParse, "err", "Empty File", "path", path)
	}
	if err := yaml.Unmarshal(data, &interfaces); err != nil {
		return nil, nil, common.NewCError(ErrorParse, "err", err, "path", path)
	}
	ingress, egress := interfaces.toContainers()
	return ingress, egress, nil
}

func (ifConfigs *IfConfigs) toContainers() (map[common.IFIDType]IFEContainer, map[common.IFIDType]IFEContainer) {
	return ifConfigs.toIngressContainer(), ifConfigs.toEgressContainer()
}

func (ifConfigs *IfConfigs) toEgressContainer() map[common.IFIDType]IFEContainer {
	containerMap := make(map[common.IFIDType]IFEContainer)
	for _, config := range ifConfigs.Interfaces {
		ifid := config.Ifid
		maxCapa := config.MaxECapa
		egressConfig := config.Egress
		if len(egressConfig) != 0 {
			container, reservedBW := mapToContainer(egressConfig, ifid, "egress")

			if reservedBW > maxCapa {
				log.Warn(fmt.Sprintf("For interface %d more egress capacity than available is reserved."+
					" This can lead to unexpected behaviour."+
					" Reserved capacity: %d Max capacity: %d", ifid, reservedBW, maxCapa))
			}

			container.maxIfBw = maxCapa
			container.ifMovAvg = NewMovingAverage(5, 1000*time.Millisecond)
			containerMap[ifid] = container
		}
	}
	return containerMap
}

func (ifConfigs *IfConfigs) toIngressContainer() map[common.IFIDType]IFEContainer {
	containerMap := make(map[common.IFIDType]IFEContainer)
	for _, config := range ifConfigs.Interfaces {
		ifid := config.Ifid
		maxCapa := config.MaxICapa
		ingressConfig := config.Ingress
		if len(ingressConfig) != 0 {
			container, reservedBW := mapToContainer(ingressConfig, ifid, "ingress")

			if reservedBW > maxCapa {
				log.Warn(fmt.Sprintf("For interface %d more ingress capacity than available is reserved."+
					" This can lead to unexpected behaviour."+
					" Reserved capacity: %d Max capacity: %d", ifid, reservedBW, maxCapa))
			}

			container.maxIfBw = maxCapa
			container.ifMovAvg = NewMovingAverage(5, 1000*time.Millisecond)
			containerMap[ifid] = container
		}
	}
	return containerMap
}

func mapToContainer(config map[string]int64, ifid common.IFIDType, typ string) (IFEContainer, int64) {
	maxUnknownBW := int64(0)
	reservedBW := int64(0)
	avgs := make(map[uint32]*ASEInformation)

	if elem, exists := config[unknown]; exists {
		maxUnknownBW = elem
		reservedBW += elem
		delete(config, unknown)
	}

	unknown := ASEInformation{
		maxBw:   maxUnknownBW,
		alertBW: (maxUnknownBW * 95) / 100,
		movAvg:  NewMovingAverage(5, 1000*time.Millisecond),
		Labels:  prometheus.Labels{"sock": fmt.Sprintf("intf:%d, as:%s", ifid, "unknown"), "type": typ},
	}

	for isd, elem := range config {
		isdas, err := addr.IAFromString(isd)
		if err != nil {
			log.Warn("Not able to parse ISDAS-ID", "err", err)
			continue
		}

		info := &ASEInformation{
			maxBw:   elem,
			alertBW: (elem * 95) / 100,
			movAvg:  NewMovingAverage(5, 1000*time.Millisecond),
			Labels:  prometheus.Labels{"sock": fmt.Sprintf("intf:%d, as:%s", ifid, isd), "type": typ},
		}

		reservedBW += elem
		key := isdas.Uint32()
		avgs[key] = info
	}

	return IFEContainer{avgs: avgs, unknown: unknown}, reservedBW
}
