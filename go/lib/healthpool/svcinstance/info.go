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
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
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
func (i Info) Addr() *addr.AppAddr {
	return i.info.addrCopy()
}

// Name returns the service instance name.
func (i Info) Name() string {
	return i.info.name
}

type info struct {
	healthpool.Info
	mtx  sync.RWMutex
	addr *addr.AppAddr
	name string
}

func (i *info) addrCopy() *addr.AppAddr {
	i.mtx.RLock()
	defer i.mtx.RUnlock()
	return i.addr.Copy()
}

func (i *info) update(a *addr.AppAddr) {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	if !a.Equal(i.addr) {
		i.addr = a
		i.ResetCount()
	}
}
