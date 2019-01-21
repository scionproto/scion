// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Package router implements an IPv4/IPv6 router. The routes map destination
// addresses to ring buffers.
package router

import (
	"net"
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ringbuf"
)

var NetMap NetMapI = &Networks{}

type NetMapI interface {
	Add(*net.IPNet, addr.IA, *ringbuf.Ring) error
	Delete(*net.IPNet) error
	Lookup(net.IP) (addr.IA, *ringbuf.Ring)
}

// Networks is an unordered mapping of non-overlapping IP allocations to ASes. It is
// concurrency safe. It is intended to be a stand-in until we have a a proper
// mapping type, as the lookup is O(n) for the number of networks it contains.
type Networks struct {
	m    sync.RWMutex
	nets []*network
}

func (ns *Networks) Add(ipnet *net.IPNet, ia addr.IA, ring *ringbuf.Ring) error {
	if ia.IsWildcard() {
		return common.NewBasicError("Networks.Add(): Illegal wildcard remote AS", nil, "ia", ia)
	}
	if ring == nil {
		return common.NewBasicError("Networks.Add(): ringBuf.Ring must not be nil", nil, "ia", ia)
	}
	cnet := newCanonNet(ipnet)
	ns.m.Lock()
	defer ns.m.Unlock()
	newNet := &network{cnet, ia, ring}
	for _, exnet := range ns.nets {
		if exnet.net.Contains(cnet.IP) || cnet.Contains(exnet.net.IP) {
			return common.NewBasicError("Networks.Add(): Networks overlap", nil,
				"new", newNet, "existing", exnet)
		}
	}
	ns.nets = append(ns.nets, newNet)
	return nil
}

func (ns *Networks) Delete(ipnet *net.IPNet) error {
	cnet := newCanonNet(ipnet)
	ns.m.Lock()
	defer ns.m.Unlock()
	idx := ns.getIdxL(cnet)
	if idx < 0 {
		return common.NewBasicError("Networks.Delete(): IPNet entry not present", nil, "net", ipnet)
	}
	// Fast delete, as it doesn't preserve order.
	// https://github.com/golang/go/wiki/SliceTricks#delete-without-preserving-order
	l := len(ns.nets)
	ns.nets[idx] = ns.nets[l-1] // Copy last element to index i
	ns.nets[l-1] = nil          // Zero last element, to allow it to be garbage collected.
	ns.nets = ns.nets[:l-1]
	return nil
}

func (ns *Networks) Lookup(ip net.IP) (addr.IA, *ringbuf.Ring) {
	ns.m.RLock()
	defer ns.m.RUnlock()
	for _, n := range ns.nets {
		if n.net.Contains(ip) {
			return n.ia, n.ring
		}
	}
	return addr.IA{}, nil
}

func (ns *Networks) getIdxL(cnet *canonNet) int {
	for i, n := range ns.nets {
		if n.net.Equal(cnet) {
			return i
		}
	}
	return -1
}

type network struct {
	net  *canonNet
	ia   addr.IA
	ring *ringbuf.Ring
}

// canonNet contains a canonicalized version of net.IPNet, which allows it to
// be tested for equality.
type canonNet struct {
	*net.IPNet
}

func newCanonNet(ipnet *net.IPNet) *canonNet {
	cn := &canonNet{&net.IPNet{}}
	// Canonicalize the IP
	cn.IP = ipnet.IP.Mask(ipnet.Mask)
	cn.Mask = append([]byte(nil), ipnet.Mask...)
	return cn
}

func (cn *canonNet) Equal(other *canonNet) bool {
	if cn == nil || other == nil {
		return cn == other
	}
	return cn.Mask.String() == other.Mask.String() && cn.IP.Equal(other.IP)
}
