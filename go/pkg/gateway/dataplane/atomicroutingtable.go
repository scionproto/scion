// Copyright 2020 Anapaya Systems

package dataplane

import (
	"sync"

	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/pkg/gateway/control"
)

// AtomicRoutingTable implements a routing table safe for concurrent use that can
// be swapped-out for a fresh table.
//
// An AtomicRoutingTable{} is a valid configuration. A routing table in its initial state
// will always return nil for routing requests, and a SetRoute will be a no-op.
//
// An AtomicRoutingTable should not be copied after use.
type AtomicRoutingTable struct {
	// FIXME(scrye): Performance might be better with an atomic pointer. We should
	// investigate if it's worth refactoring, because code with atomics will be harder
	// to read.

	// mtx protects read and write access to the routing table pointer. This does not include access
	// to the table itself; as soon as the pointer to the table is read, the table operations
	// will happen outside the mutex-protected area.
	mtx   sync.RWMutex
	table control.RoutingTable
}

func (t *AtomicRoutingTable) RouteIPv4(packet layers.IPv4) control.PktWriter {
	table := t.getPointer()
	if table == nil {
		return nil
	}
	return table.RouteIPv4(packet)
}

func (t *AtomicRoutingTable) RouteIPv6(packet layers.IPv6) control.PktWriter {
	table := t.getPointer()
	if table == nil {
		return nil
	}
	return table.RouteIPv6(packet)
}

func (t *AtomicRoutingTable) AddRoute(index int, pktWriter control.PktWriter) error {
	table := t.getPointer()
	if table == nil {
		return nil
	}
	return table.AddRoute(index, pktWriter)
}

func (t *AtomicRoutingTable) DelRoute(index int) error {
	table := t.getPointer()
	if table == nil {
		return nil
	}
	return table.DelRoute(index)
}

func (t *AtomicRoutingTable) SetRoutingTable(table control.RoutingTable) {
	t.setPointer(table)
}

func (t *AtomicRoutingTable) getPointer() control.RoutingTable {
	t.mtx.RLock()
	defer t.mtx.RUnlock()
	return t.table
}

func (t *AtomicRoutingTable) setPointer(table control.RoutingTable) {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	t.table = table
}
