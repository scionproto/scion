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
	"slices"
	"sync"

	"github.com/scionproto/scion/pkg/addr"
)

// A generic anycast address map. This could in fact be generalized to be a key->anyOneValue
// with no specific networking semantics, but there's no obvious other usage at the moment.
// This is for use by all underlay providers to implement the service mapping.
type Services[addrT comparable] struct {
	mtx sync.Mutex
	m   map[addr.SVC][]addrT
}

func NewServices[addrT comparable]() *Services[addrT] {
	return &Services[addrT]{m: make(map[addr.SVC][]addrT)}
}

func (s *Services[addrT]) AddSvc(svc addr.SVC, a addrT) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrs := s.m[svc]
	if slices.Contains(addrs, a) {
		return
	}
	s.m[svc] = append(addrs, a)
}

func (s *Services[addrT]) DelSvc(svc addr.SVC, a addrT) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrs := s.m[svc]
	index := slices.Index(addrs, a)
	if index == -1 {
		return
	}
	addrs[index] = addrs[len(addrs)-1]
	var zeroAddr addrT
	addrs[len(addrs)-1] = zeroAddr
	s.m[svc] = addrs[:len(addrs)-1]
}

func (s *Services[addrT]) Any(svc addr.SVC) (addrT, bool) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	addrs := s.m[svc]
	if len(addrs) == 0 {
		var zeroAddr addrT
		return zeroAddr, false
	}
	return addrs[rand.IntN(len(addrs))], true
}
