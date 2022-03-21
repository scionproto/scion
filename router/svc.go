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
	mrand "math/rand"
	"net"
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
)

type services struct {
	mtx sync.Mutex
	m   map[addr.HostSVC][]*net.UDPAddr
}

func newServices() *services {
	return &services{m: make(map[addr.HostSVC][]*net.UDPAddr)}
}

func (s *services) AddSvc(svc addr.HostSVC, a *net.UDPAddr) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrs := s.m[svc]
	if _, ok := s.index(a, addrs); ok {
		return
	}
	s.m[svc] = append(addrs, a)
}

func (s *services) DelSvc(svc addr.HostSVC, a *net.UDPAddr) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrs := s.m[svc]
	index, ok := s.index(a, addrs)
	if !ok {
		return
	}
	addrs[index] = addrs[len(addrs)-1]
	addrs[len(addrs)-1] = nil
	s.m[svc] = addrs[:len(addrs)-1]
}

func (s *services) Any(svc addr.HostSVC) (*net.UDPAddr, bool) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrs := s.m[svc]
	if len(addrs) == 0 {
		return nil, false
	}
	return addrs[mrand.Intn(len(addrs))], true
}

func (s *services) index(a *net.UDPAddr, addrs []*net.UDPAddr) (int, bool) {
	for i, o := range addrs {
		if a.IP.Equal(o.IP) && a.Port == o.Port {
			return i, true
		}
	}
	return -1, false
}
