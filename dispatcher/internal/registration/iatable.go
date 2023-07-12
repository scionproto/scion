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
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/common"
)

const (
	ErrBadISD common.ErrMsg = "0 is not valid ISD"
	ErrBadAS  common.ErrMsg = "0 is not valid AS"
)

// Reference tracks an object from a collection.
type Reference interface {
	// Free removes the object from its parent collection, cleaning up any allocations.
	Free()
}

type RegReference interface {
	Reference
	// UDPAddr returns the UDP address associated with this reference
	UDPAddr() *net.UDPAddr
	// SVCAddr returns the SVC address associated with this reference. If no
	// SVC address is associated, it returns SvcNone.
	SVCAddr() addr.SVC
	// RegisterID attaches an SCMP ID to this reference. The ID is released
	// when the reference is freed. Registering another ID does not overwrite
	// the previous; instead, multiple IDs get associated with the reference.
	// SCMP messages targeted at the ID will get sent to the socket associated
	// with the reference. The IA of the id is set to the IA of the reference.
	RegisterID(id uint64) error
}

// IATable manages the UDP/IP port registrations for a SCION Dispatcher.
//
// IATable is safe for concurrent use from multiple goroutines.
type IATable interface {
	// Register a new entry for AS ia with the specified public, bind and
	// services addresses and associate a value with the entry. Lookup calls
	// for matching addresses will return the associated value.
	//
	// A LookupPublic call will select an entry with a matching public address.
	// For IPv4, this is either a perfect match or a 0.0.0.0 entry. For IPv6,
	// this is either a perfect match or a :: entry. If the public address to
	// register matches an existing entry, an error is returned. Using port 0
	// for the public address will allocate a valid port.
	//
	// A LookupService call will select an entry with matching bind and service
	// addresses. Binds for 0.0.0.0 or :: are not allowed. The port is
	// inherited from the public address. To not register for a service, use a
	// bind of nil and a svc of none. For more information about SVC behavior,
	// see the documentation for SVCTable.
	//
	// To unregister from the table, free the returned reference.
	Register(ia addr.IA, public *net.UDPAddr, bind net.IP, svc addr.SVC,
		value interface{}) (RegReference, error)
	// LookupPublic returns the value associated with the selected public
	// address. Wildcard addresses are supported. If an entry is found, the
	// returned boolean is set to true. Otherwise, it is set to false.
	LookupPublic(ia addr.IA, public *net.UDPAddr) (interface{}, bool)
	// LookupService returns the entries associated with svc and bind.
	//
	// If SVC is an anycast address, at most one entry is returned. The bind
	// address is used to narrow down the set of possible entries. If multiple
	// entries exist, one is selected arbitrarily.
	//
	// Note that nil bind addresses are supported for anycasts (the address is
	// in this case ignored), but support for this might be dropped in the
	// future.
	//
	// If SVC is a multicast address, more than one entry can be returned. The
	// bind address is ignored in this case.
	LookupService(ia addr.IA, svc addr.SVC, bind net.IP) []interface{}
	// LookupID returns the entry associated with the SCMP General class ID id.
	// The ID is used for SCMP Echo, TraceRoute, and RecordPath functionality.
	// If an entry is found, the returned boolean is set to true. Otherwise, it
	// is set to false.
	LookupID(ia addr.IA, id uint64) (interface{}, bool)
}

// NewIATable creates a new UDP/IP port registration table.
//
// If the public address in a registration contains the port 0, a free port is
// allocated between minPort and maxPort.
//
// If minPort is <= 0 or maxPort is > 65535, the function panics.
func NewIATable(minPort, maxPort int) IATable {
	return newIATable(minPort, maxPort)
}

var _ IATable = (*iaTable)(nil)

type iaTable struct {
	mtx     sync.RWMutex
	ia      map[addr.IA]*Table
	minPort int
	maxPort int
}

func newIATable(minPort, maxPort int) *iaTable {
	return &iaTable{
		ia:      make(map[addr.IA]*Table),
		minPort: minPort,
		maxPort: maxPort,
	}
}

func (t *iaTable) Register(ia addr.IA, public *net.UDPAddr, bind net.IP, svc addr.SVC,
	value interface{}) (RegReference, error) {

	t.mtx.Lock()
	defer t.mtx.Unlock()
	if ia.ISD() == 0 {
		return nil, ErrBadISD
	}
	if ia.AS() == 0 {
		return nil, ErrBadAS
	}
	table, ok := t.ia[ia]
	if !ok {
		table = NewTable(t.minPort, t.maxPort)
		t.ia[ia] = table
	}
	reference, err := table.Register(public, bind, svc, value)
	if err != nil {
		return nil, err
	}
	return &iaTableReference{
		table:    t,
		ia:       ia,
		entryRef: reference,
		svc:      svc,
		value:    value,
	}, nil
}

func (t *iaTable) LookupPublic(ia addr.IA, public *net.UDPAddr) (interface{}, bool) {
	t.mtx.RLock()
	defer t.mtx.RUnlock()
	if table, ok := t.ia[ia]; ok {
		return table.LookupPublic(public)
	}
	return nil, false
}

func (t *iaTable) LookupService(ia addr.IA, svc addr.SVC, bind net.IP) []interface{} {
	t.mtx.RLock()
	defer t.mtx.RUnlock()
	if table, ok := t.ia[ia]; ok {
		return table.LookupService(svc, bind)
	}
	return nil
}

func (t *iaTable) LookupID(ia addr.IA, id uint64) (interface{}, bool) {
	t.mtx.RLock()
	defer t.mtx.RUnlock()
	if table, ok := t.ia[ia]; ok {
		return table.LookupID(id)
	}
	return nil, false
}

var _ RegReference = (*iaTableReference)(nil)

type iaTableReference struct {
	table    *iaTable
	ia       addr.IA
	entryRef *TableReference
	svc      addr.SVC
	// value is the main table information associated with this reference
	value interface{}
}

func (r *iaTableReference) Free() {
	r.table.mtx.Lock()
	defer r.table.mtx.Unlock()
	r.entryRef.Free()
	if r.table.ia[r.ia].Size() == 0 {
		delete(r.table.ia, r.ia)
	}
}

func (r *iaTableReference) UDPAddr() *net.UDPAddr {
	return r.entryRef.UDPAddr()
}

func (r *iaTableReference) SVCAddr() addr.SVC {
	return r.svc
}

func (r *iaTableReference) RegisterID(id uint64) error {
	r.table.mtx.Lock()
	defer r.table.mtx.Unlock()
	return r.entryRef.RegisterID(id, r.value)
}
