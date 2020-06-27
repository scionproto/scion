// Copyright 2020 Anapaya Systems
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

package integration

import (
	"io/ioutil"
	"net"

	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

type networkAllocs struct {
	Testers map[addr.IA]string `yaml:"testers"`
}

func LoadNetworkAllocs() (map[addr.IA]*snet.UDPAddr, error) {
	raw, err := ioutil.ReadFile(GenFile("network-allocations.yml"))
	if err != nil {
		return nil, nil
	}
	var allocs networkAllocs
	if err := yaml.Unmarshal(raw, &allocs); err != nil {
		return nil, err
	}
	addrs = make(map[addr.IA]*snet.UDPAddr, len(allocs.Testers))
	for ia, tester := range allocs.Testers {
		addrs[ia] = &snet.UDPAddr{IA: ia, Host: &net.UDPAddr{IP: net.ParseIP(tester)}}
	}
	return addrs, nil
}
