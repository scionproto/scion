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

package router

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"

	"github.com/scionproto/scion/pkg/addr"
)

type services struct {
	mtx sync.Mutex
	m   map[addr.SVC][]netip.AddrPort
}

func newServices() *services {
	return &services{m: make(map[addr.SVC][]netip.AddrPort)}
}

func (s *services) AddSvc(svc addr.SVC, a netip.AddrPort) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrs := s.m[svc]
	if slices.Contains(addrs, a) {
		return
	}
	s.m[svc] = append(addrs, a)
}

func (s *services) DelSvc(svc addr.SVC, a netip.AddrPort) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrs := s.m[svc]
	index := slices.Index(addrs, a)
	if index == -1 {
		return
	}
	addrs[index] = addrs[len(addrs)-1]
	addrs[len(addrs)-1] = netip.AddrPort{}
	s.m[svc] = addrs[:len(addrs)-1]
}

func (s *services) Any(svc addr.SVC) (netip.AddrPort, bool) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrs := s.m[svc]
	if len(addrs) == 0 {
		return netip.AddrPort{}, false
	}
	return addrs[rand.IntN(len(addrs))], true
}
