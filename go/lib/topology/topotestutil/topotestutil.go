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

package topotestutil

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

func AddServer(topo *topology.Topo, svc proto.ServiceType, name string,
	topoAddr topology.TopoAddr) {

	switch svc {
	case proto.ServiceType_bs:
		topo.BSNames = append(topo.BSNames, name)
		topo.BS[name] = topoAddr
	case proto.ServiceType_ps:
		topo.PSNames = append(topo.PSNames, name)
		topo.PS[name] = topoAddr
	case proto.ServiceType_cs:
		topo.CSNames = append(topo.CSNames, name)
		topo.CS[name] = topoAddr
	case proto.ServiceType_sb:
		topo.SBNames = append(topo.SBNames, name)
		topo.SB[name] = topoAddr
	default:
		panic(fmt.Sprintf("service type error %v", svc))
	}
}
