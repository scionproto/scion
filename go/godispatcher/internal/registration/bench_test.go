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

package registration

import (
	"net"
	"testing"

	"github.com/scionproto/scion/go/lib/addr"
)

type registerArgs struct {
	ia     addr.IA
	public *net.UDPAddr
	bind   net.IP
	svc    addr.HostSVC
	value  interface{}
}

func generateRegisterArgs(n int) []*registerArgs {
	var data []*registerArgs
	for i := 0; i < n; i++ {
		newData := &registerArgs{
			ia:     getRandomIA(),
			public: getRandomUDPAddress(),
			bind:   getRandomIPv4(),
			svc:    getRandomSVC(),
			value:  getRandomValue(),
		}
		data = append(data, newData)
	}
	return data
}

func generateLookupPublicArgs(n int) []*net.UDPAddr {
	var data []*net.UDPAddr
	for i := 0; i < n; i++ {
		data = append(data, getRandomUDPAddress())
	}
	return data
}

func BenchmarkRegister(b *testing.B) {
	table := NewIATable(minPort, maxPort)
	regData := generateRegisterArgs(b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		table.Register(regData[n].ia, regData[n].public, nil, addr.SvcNone, regData[n].value)
	}
}

func BenchmarkLookupPublicIPv4(b *testing.B) {
	numEntries := 1000
	table := NewIATable(minPort, maxPort)
	regData := generateRegisterArgs(numEntries)
	for i := 0; i < numEntries; i++ {
		table.Register(regData[i].ia, regData[i].public, nil, addr.SvcNone, regData[i].value)
	}
	lookupData := generateLookupPublicArgs(b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		table.LookupPublic(addr.IA{I: 1, A: 1}, lookupData[n])
	}
}

type lookupServiceArgs struct {
	svc  addr.HostSVC
	bind net.IP
}

func generateLookupServiceArgs(n int) []*lookupServiceArgs {
	var data []*lookupServiceArgs
	for i := 0; i < n; i++ {
		data = append(data, &lookupServiceArgs{
			svc:  getRandomSVC(),
			bind: getRandomIPv4(),
		})
	}
	return data
}

func BenchmarkLookupServiceIPv4(b *testing.B) {
	numEntries := 1000
	table := NewIATable(minPort, maxPort)
	regData := generateRegisterArgs(numEntries)
	for i := 0; i < numEntries; i++ {
		table.Register(regData[i].ia, regData[i].public, regData[i].bind,
			regData[i].svc, regData[i].value)
	}
	lookupData := generateLookupServiceArgs(b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		table.LookupService(addr.IA{I: 1, A: 1}, lookupData[n].svc, lookupData[n].bind)
	}
}
