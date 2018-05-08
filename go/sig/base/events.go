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

// NetworkChangedParams contains the parameters that are passed along with a NetworkChanged event.
type NetworkChangedParams struct {
	// RemoteIA is the remote IA for which network information changed.
	RemoteIA addr.IA
	// IpNet contains the network prefix that was added/removed.
	IpNet net.IPNet
	// Added is true if the prefix was added, false otherwise.
	Added bool
}

// SigChangedParams contains the parameters that are passed along with a SigChanged event.
type SigChangedParams struct {
	// RemoteIA is the IA for which SIG information changed.
	RemoteIA addr.IA
	// Id is the id of the SIG.
	Id siginfo.SigIdType
	// Host is the host address of the SIG.
	Host addr.HostAddr
	// CtrlPort is the port on which the SIG accepts control traffic.
	CtrlPort int
	// EncapPort is the port on which the SIG accepts encapsulated SIG-SIG frames.
	EncapPort int
	// Static is true, if this SIG was statically configured and false if it was discovered
	// dynamically.
	Static bool
	// Added is true if the SIG was added, false otherwise.
	Added bool
}

// RemoteHealthChangedParams contains the parameters that are passed along with a
// RemoteHealthChanged event.
type RemoteHealthChangedParams struct {
	// RemoteIA is the IA for which the reachability status changed.
	RemoteIA addr.IA
	// Nets contains all network prefixes the remote IA announced.
	Nets []*net.IPNet
	// Healthy is true if the remote IA is reachable, false otherwise.
	Healthy bool
}

// EventCallbacks can be used by a listener to register for certain events by setting the
// corresponding function pointer in the struct. Note, that the callback MUST NOT BLOCK. Long
// running or potentially blocking operations should be executed in a separate go-routine.
type EventCallbacks struct {
	// NetworkChanged is called when a remote network was added or removed from the configuration.
	NetworkChanged NetworkChangedCb
	// SigChanged is called when a remote SIG is was added or removed from the configuration.
	// TODO(shitz): This event does not get generated yet.
	SigChanged SigChangedCb
	// RemoteHealthChanged is called when the reachability status of a remote AS changed.
	RemoteHealthChanged RemoteHealthChangedCb
}

var lock sync.RWMutex
var listeners = make(map[string]EventCallbacks)

func AddEventListener(listenerName string, cbs EventCallbacks) {
	lock.Lock()
	defer lock.Unlock()
	listeners[listenerName] = cbs
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
			cbs.NetworkChanged(params)
		}
	}
}

func RemoteHealthChanged(params RemoteHealthChangedParams) {
	lock.RLock()
	defer lock.RUnlock()
	for _, cbs := range listeners {
		if cbs.RemoteHealthChanged != nil {
			cbs.RemoteHealthChanged(params)
		}
	}
}

func SigChanged(params SigChangedParams) {
	lock.RLock()
	defer lock.RUnlock()
	for _, cbs := range listeners {
		if cbs.SigChanged != nil {
			cbs.SigChanged(params)
		}
	}
}
