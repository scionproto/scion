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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

// Table manages the UDP/IP port registrations for a single AS.
//
// Table is not safe for concurrent use from multiple goroutines.
type Table struct {
	udpPortTable *UDPPortTable
	svcTable     SVCTable
	size         int
	ids          []uint64
	// XXX(scrye): Note that SCMP General IDs are globally scoped inside an IA
	// (i.e., all all hosts share the same ID namespace, and thus can collide
	// with each other). Because the IDs are random, it is very unlikely for a
	// collision to occur (although faulty coding can increase the chance,
	// e.g., if apps start with an ID of 1 and increment from there). We should
	// revisit if SCMP General IDs should be scoped to IPs.
	scmpTable *SCMPTable
}

func NewTable(minPort, maxPort int) *Table {
	return &Table{
		udpPortTable: NewUDPPortTable(minPort, maxPort),
		svcTable:     NewSVCTable(),
		scmpTable:    NewSCMPTable(),
	}
}

func (t *Table) Register(public *net.UDPAddr, bind net.IP, svc addr.HostSVC,
	value interface{}) (*TableReference, error) {

	if public == nil {
		return nil, common.NewBasicError(ErrNoPublicAddress, nil)
	}
	if bind != nil && svc == addr.SvcNone {
		return nil, common.NewBasicError(ErrBindWithoutSvc, nil)
	}
	address, err := t.udpPortTable.Insert(public, value)
	if err != nil {
		return nil, err
	}
	if bind == nil {
		bind = public.IP
	}
	svcRef, err := t.insertSVCIfRequested(svc, bind, public.Port, value)
	if err != nil {
		t.udpPortTable.Remove(public)
		return nil, err
	}
	t.size++
	return &TableReference{table: t, address: address, svcRef: svcRef}, nil
}

func (t *Table) insertSVCIfRequested(svc addr.HostSVC, bind net.IP, port int,
	value interface{}) (Reference, error) {

	if svc != addr.SvcNone {
		bindUdpAddr := &net.UDPAddr{
			IP:   bind,
			Port: port,
		}
		return t.svcTable.Register(svc, bindUdpAddr, value)
	}
	return nil, nil
}

func (t *Table) LookupPublic(address *net.UDPAddr) (interface{}, bool) {
	return t.udpPortTable.Lookup(address)
}

func (t *Table) LookupService(svc addr.HostSVC, bind net.IP) []interface{} {
	return t.svcTable.Lookup(svc, bind)
}

func (t *Table) Size() int {
	return t.size
}

func (t *Table) LookupID(id uint64) (interface{}, bool) {
	return t.scmpTable.Lookup(id)
}

func (t *Table) registerID(id uint64, value interface{}) error {
	return t.scmpTable.Register(id, value)
}

func (t *Table) removeID(id uint64) {
	t.scmpTable.Remove(id)
}

type TableReference struct {
	table   *Table
	freed   bool
	address *net.UDPAddr
	svcRef  Reference
	ids     []uint64
}

func (r *TableReference) Free() {
	if r.freed {
		panic("double free")
	}
	r.freed = true
	r.table.udpPortTable.Remove(r.address)
	if r.svcRef != nil {
		r.svcRef.Free()
	}
	r.table.size--
	for _, id := range r.ids {
		r.table.removeID(id)
	}
}

func (r *TableReference) UDPAddr() *net.UDPAddr {
	return r.address
}

func (r *TableReference) RegisterID(id uint64, value interface{}) error {
	if err := r.table.registerID(id, value); err != nil {
		return err
	}
	r.ids = append(r.ids, id)
	return nil
}
