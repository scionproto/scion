// Copyright 2017 ETH Zurich
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

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/sig/lib/scion"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

// Topology contains the aggregated information for remote SIGs, ASes and their prefixes
type Topology struct {
	// TODO(scrye) per AS lock granularity
	lock     sync.RWMutex
	topo     *asMap
	scionNet *scion.SCIONNet
}

func NewTopology(scionNet *scion.SCIONNet) (*Topology, error) {
	topology := new(Topology)
	topology.topo = newASMap()
	topology.scionNet = scionNet
	// FIXME(scrye): reactivate keepalive module
	//sdb.helloModule = hello.NewModule()
	return topology, nil
}

func (sdb *Topology) AddRoute(prefix string, isdas string) error {
	sdb.lock.RLock()
	defer sdb.lock.RUnlock()

	_, subnet, err := net.ParseCIDR(prefix)
	if err != nil {
		return err
	}

	info, found := sdb.topo.get(isdas)
	if !found {
		return common.NewCError("Unable to add prefix for unreachable AS", "AS", isdas, "prefix",
			prefix)
	}

	err = info.addRoute(subnet)
	if err != nil {
		return err
	}

	// TODO define consistency model between this information and the Linux routing table
	err = xnet.AddRouteIF(subnet, info.DeviceName)
	if err != nil {
		log.Error("Unable to add route", "subnet", subnet, "device", info.DeviceName)
		return err
	}
	return nil
}

func (sdb *Topology) DelRoute(prefix string, isdas string) error {
	sdb.lock.RLock()
	defer sdb.lock.RUnlock()

	_, subnet, err := net.ParseCIDR(prefix)
	if err != nil {
		return err
	}

	// TODO delete from routing table
	info, found := sdb.topo.get(isdas)
	if !found {
		return common.NewCError("Unable to delete prefix from unreachable AS", "prefix",
			prefix, "AS", isdas)
	}
	return info.delRoute(subnet)
}

func (sdb *Topology) AddSig(isdas string, encapAddr string, encapPort string, ctrlAddr string, ctrlPort string, source string) error {
	sdb.lock.Lock()
	defer sdb.lock.Unlock()

	var err error
	if e, ok := sdb.topo.get(isdas); ok {
		return e.addSig(encapAddr, encapPort, ctrlAddr, ctrlPort, source)
	}

	// Create tunnel interface for remote AS
	info, err := newASInfo(sdb.scionNet, isdas)
	if err != nil {
		return err
	}
	sdb.topo.set(isdas, info)

	// FIXME(scrye) channel for worker commands (to cancel goroutine when remote AS is removed)
	ework := NewEgressWorker(info)
	go ework.Run()
	return info.addSig(encapAddr, encapPort, ctrlAddr, ctrlPort, source)
}

func (sdb *Topology) DelSig(isdas string, address string, port string, source string) error {
	sdb.lock.Lock()
	defer sdb.lock.Unlock()

	if e, found := sdb.topo.get(isdas); found {
		return e.delSig(address, port, source)
	}
	return common.NewCError("SIG entry not found", "address", address, "port", port)
}

func (sdb *Topology) Print(source string) string {
	sdb.lock.RLock()
	defer sdb.lock.RUnlock()
	return sdb.topo.print()
}

// asMap keeps track of which ASes have been defined
type asMap struct {
	info map[string]*asInfo
	lock sync.RWMutex
}

func newASMap() *asMap {
	topo := &asMap{}
	topo.info = make(map[string]*asInfo)
	return topo
}

func (t *asMap) get(key string) (*asInfo, bool) {
	t.lock.RLock()
	defer t.lock.RUnlock()
	v, ok := t.info[key]
	return v, ok
}

func (t *asMap) set(key string, value *asInfo) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.info[key] = value
}

func (t *asMap) print() string {
	t.lock.RLock()
	defer t.lock.RUnlock()
	output := ""
	for _, v := range t.info {
		output += v.String()
	}
	return output
}
