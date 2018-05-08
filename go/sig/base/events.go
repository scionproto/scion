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

package base

import (
	"net"
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/sig/siginfo"
)

type (
	NetworkChangedCb      func(NetworkChangedParams)
	RemoteHealthChangedCb func(RemoteHealthChangedParams)
	SigChangedCb          func(SigChangedParams)
)

type NetworkChangedParams struct {
	RemoteIA addr.IA
	IpNet    net.IPNet
	Added    bool
}

type RemoteHealthChangedParams struct {
	RemoteIA addr.IA
	Nets     map[string]*net.IPNet
	Healthy  bool
}

type SigChangedParams struct {
	RemoteIA  addr.IA
	Id        siginfo.SigIdType
	Host      addr.HostAddr
	CtrlPort  int
	EncapPort int
	Static    bool
	Added     bool
}

type EventCallbacks struct {
	NetworkChanged      NetworkChangedCb
	SigChanged          SigChangedCb
	RemoteHealthChanged RemoteHealthChangedCb
}

var lock sync.RWMutex
var listeners map[string]EventCallbacks = make(map[string]EventCallbacks)

func AddEventListener(moduleName string, cbs EventCallbacks) {
	lock.Lock()
	defer lock.Unlock()
	listeners[moduleName] = cbs
}

func RemoveEventListener(listenerName string) {
	lock.Lock()
	defer lock.Unlock()
	delete(listeners, listenerName)
}

func NetworkChanged(params NetworkChangedParams) {
	lock.RLock()
	defer lock.RUnlock()
	for _, cbs := range listeners {
		if cbs.NetworkChanged != nil {
			go cbs.NetworkChanged(params)
		}
	}
}

func RemoteHealthChanged(params RemoteHealthChangedParams) {
	lock.RLock()
	defer lock.RUnlock()
	for _, cbs := range listeners {
		if cbs.RemoteHealthChanged != nil {
			go cbs.RemoteHealthChanged(params)
		}
	}
}

func SigChanged(params SigChangedParams) {
	lock.RLock()
	defer lock.RUnlock()
	for _, cbs := range listeners {
		if cbs.SigChanged != nil {
			go cbs.SigChanged(params)
		}
	}
}
