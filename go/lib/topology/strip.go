// Copyright 2017 ETH Zurich
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
	"github.com/netsec-ethz/scion/go/lib/common"
)

func StripServices(rt *RawTopo) {
	// Clear services that don't need to be publicly visible
	rt.BeaconService = make(map[string]RawAddrInfo)
	rt.SibraService = make(map[string]RawAddrInfo)
	rt.ZookeeperService = make(map[int]RawAddrPort)
}

func StripBind(rt *RawTopo) {
	// These services may have Bind sections that we need to remove
	removeSVCBind(rt.CertificateService)
	removeSVCBind(rt.PathService)
	removeSVCBind(rt.RainsService)
	removeSVCBind(rt.DiscoveryService)

	// Border Routers have Bind sections plus other link-specific information that we want to trim
	removeBRBind(rt.BorderRouters)
}

func removeSVCBind(srv map[string]RawAddrInfo) {
	for name, s := range srv {
		srv[name] = RawAddrInfo{Public: s.Public}
	}
}

func removeBRBind(brs map[string]RawBRInfo) {
	for name, bri := range brs {
		newIntAddrs := make([]RawAddrInfo, 0)
		for _, ia := range bri.InternalAddrs {
			newIntAddrs = append(newIntAddrs, RawAddrInfo{Public: ia.Public})
		}
		newifs := make(map[common.IFIDType]RawBRIntf, 0)
		for id, brintf := range bri.Interfaces {
			// The nil elements are of no interest to the public
			newifs[id] = RawBRIntf{
				InternalAddrIdx: brintf.InternalAddrIdx,
				Overlay:         "",
				Bind:            nil,
				Public:          nil,
				Remote:          nil,
				Bandwidth:       brintf.Bandwidth,
				ISD_AS:          brintf.ISD_AS,
				LinkType:        brintf.LinkType,
				MTU:             brintf.MTU,
			}
		}
		brs[name] = RawBRInfo{InternalAddrs: newIntAddrs, Interfaces: newifs}
	}
}
