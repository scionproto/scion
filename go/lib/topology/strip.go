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

func StripBind(rt *RawTopo) {
	// These services may have Bind sections that we need to remove
	removeSrvBind(rt.CertificateService)
	removeSrvBind(rt.PathService)
	removeSrvBind(rt.RainsService)
	removeSrvBind(rt.DiscoveryService)

	// Border Routers have Bind sections plus other link-specific information that we want to trim
	removeBRBind(rt.BorderRouters)
}

func StripServices(rt *RawTopo) {
	// Clear services that don't need to be publicly visible
	rt.BeaconService = make(map[string]*RawSrvInfo)
	rt.SibraService = make(map[string]*RawSrvInfo)
	rt.ZookeeperService = make(map[int]*RawAddrPort)
}

func removeSrvBind(svc map[string]*RawSrvInfo) {
	for _, s := range svc {
		removeRAMBind(s.Addrs)
	}
}

func removeBRBind(brs map[string]*RawBRInfo) {
	for _, bri := range brs {
		removeRAMBind(bri.InternalAddrs)
		for i := range bri.Interfaces {
			// The nil elements are of no interest to the public
			bri.Interfaces[i].Overlay = ""
			bri.Interfaces[i].Bind = nil
			bri.Interfaces[i].Public = nil
			bri.Interfaces[i].Remote = nil
		}
	}
}

func removeRAMBind(ram RawAddrMap) {
	for _, v := range ram {
		v.Bind = nil
	}
}
