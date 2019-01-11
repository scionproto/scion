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
}

func NewTable(minPort, maxPort int) *Table {
	return &Table{
		udpPortTable: NewUDPPortTable(minPort, maxPort),
		svcTable:     NewSVCTable(),
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

type TableReference struct {
	table   *Table
	freed   bool
	address *net.UDPAddr
	svcRef  Reference
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
}

func (r *TableReference) UDPAddr() *net.UDPAddr {
	return r.address
}
