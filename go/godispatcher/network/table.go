// Copyright 2019 ETH Zurich
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

package network

import (
	"net"

	"github.com/scionproto/scion/go/godispatcher/internal/registration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ringbuf"
)

type TableEntry struct {
	conn           net.PacketConn
	appIngressRing *ringbuf.Ring
}

func newTableEntry(conn net.PacketConn) *TableEntry {
	// Construct application ingress ring buffer
	appIngressRing := ringbuf.New(128, nil, "", nil)
	return &TableEntry{
		conn:           conn,
		appIngressRing: appIngressRing,
	}
}

func getBindIP(address *net.UDPAddr) net.IP {
	if address == nil {
		return nil
	}
	return address.IP
}

// IATable is a type-safe convenience wrapper around a generic routing table.
type IATable struct {
	registration.IATable
}

func NewIATable(minPort, maxPort int) *IATable {
	return &IATable{
		IATable: registration.NewIATable(minPort, maxPort),
	}
}

func (t *IATable) LookupPublic(ia addr.IA, public *net.UDPAddr) (*TableEntry, bool) {
	e, ok := t.IATable.LookupPublic(ia, public)
	if !ok {
		return nil, false
	}
	return e.(*TableEntry), true
}

func (t *IATable) LookupService(ia addr.IA, svc addr.HostSVC, bind net.IP) []*TableEntry {
	ifaces := t.IATable.LookupService(ia, svc, bind)
	entries := make([]*TableEntry, len(ifaces))
	for i := range ifaces {
		entries[i] = ifaces[i].(*TableEntry)
	}
	return entries
}

func (t *IATable) LookupID(id uint64) (*TableEntry, bool) {
	e, ok := t.IATable.LookupID(id)
	if !ok {
		return nil, false
	}
	return e.(*TableEntry), true
}
