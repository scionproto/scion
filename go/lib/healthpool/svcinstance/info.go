// Copyright 2019 Anapaya Systems
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

package svcinstance

import (
	"net"
	"sync"

	"github.com/scionproto/scion/go/lib/healthpool"
)

// Info holds the information for a service instance.
type Info struct {
	info *info
}

// Fail increases the fail count. It shall be called when a request to the
// service instance fails.
func (i Info) Fail() {
	i.info.Fail()
}

// Addr returns the service instance address.
func (i Info) Addr() *net.UDPAddr {
	return i.info.addrCopy()
}

// Name returns the service instance name.
func (i Info) Name() string {
	return i.info.name
}

type info struct {
	healthpool.Info
	mtx  sync.RWMutex
	addr *net.UDPAddr
	name string
}

func (i *info) addrCopy() *net.UDPAddr {
	i.mtx.RLock()
	defer i.mtx.RUnlock()
	return &net.UDPAddr{
		IP:   append(i.addr.IP[:0:0], i.addr.IP...),
		Port: i.addr.Port,
	}

}

func (i *info) update(a *net.UDPAddr) {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	if !a.IP.Equal(i.addr.IP) || a.Port != i.addr.Port {
		i.addr = a
		i.ResetCount()
	}
}
