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
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/common"
)

// UDPPortTable stores port allocations for UDP/IPv4 and UDP/IPv6 sockets.
//
// Additionally, it allocates ports dynamically if the requested port is 0.
type UDPPortTable struct {
	v4PortTable map[int]IPTable
	v6PortTable map[int]IPTable
	allocator   *UDPPortAllocator
}

func NewUDPPortTable(minPort, maxPort int) *UDPPortTable {
	return NewUDPPortTableFromMap(minPort, maxPort, make(map[int]IPTable), make(map[int]IPTable))
}

func NewUDPPortTableFromMap(minPort, maxPort int, v4, v6 map[int]IPTable) *UDPPortTable {
	return &UDPPortTable{
		v4PortTable: v4,
		v6PortTable: v6,
		allocator:   NewUDPPortAllocator(minPort, maxPort),
	}
}

func (t *UDPPortTable) Lookup(address *net.UDPAddr) (interface{}, bool) {
	if address.IP.IsUnspecified() {
		return nil, false
	}
	portTable := t.getPortTableByIP(address.IP)
	ipTable, ok := portTable[address.Port]
	if !ok {
		return nil, false
	}
	return ipTable.Route(address.IP)
}

func (t *UDPPortTable) getPortTableByIP(ip net.IP) map[int]IPTable {
	if ip.To4() != nil {
		return t.v4PortTable
	}
	return t.v6PortTable
}

func (t *UDPPortTable) overlapsWith(address *net.UDPAddr) bool {
	portTable := t.getPortTableByIP(address.IP)
	ipTable, ok := portTable[address.Port]
	if !ok {
		return false
	}
	return ipTable.OverlapsWith(address.IP)
}

// Insert adds address into the allocation table. It will return an error if an
// entry overlaps, or if the value is nil.
func (t *UDPPortTable) Insert(address *net.UDPAddr, value interface{}) (*net.UDPAddr, error) {
	if t.overlapsWith(address) {
		return nil, common.NewBasicError(ErrOverlappingAddress, nil, "address", address)
	}
	if value == nil {
		return nil, common.NewBasicError(ErrNoValue, nil)
	}
	newAddress, err := t.computeAddressWithPort(address)
	if err != nil {
		return nil, err
	}
	t.insertUDPAddress(newAddress, value)
	return newAddress, nil
}

func (t *UDPPortTable) computeAddressWithPort(address *net.UDPAddr) (*net.UDPAddr, error) {
	var err error
	address = copyUDPAddr(address)
	if address.Port == 0 {
		address.Port, err = t.allocator.Allocate(address.IP, t)
	}
	return address, err
}

func (t *UDPPortTable) insertUDPAddress(address *net.UDPAddr, value interface{}) {
	ipTable, ok := t.v4PortTable[address.Port]
	if !ok {
		ipTable = make(IPTable)
		t.v4PortTable[address.Port] = ipTable
	}
	ipTable[address.IP.String()] = value
}

func copyUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   copyIPAddr(address.IP),
		Port: address.Port,
		Zone: address.Zone,
	}
}

func copyIPAddr(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func (t *UDPPortTable) Remove(address *net.UDPAddr) {
	ipTable, ok := t.v4PortTable[address.Port]
	if ok {
		delete(ipTable, address.IP.String())
		if len(ipTable) == 0 {
			delete(t.v4PortTable, address.Port)
		}
	}
}

// IPTable maps string representations of IP addresses to arbitrary values.
type IPTable map[string]interface{}

// OverlapsWith returns true if ip overlaps with any entry in t. For example,
// 0.0.0.0 would overlap with any other IPv4 address.
func (t IPTable) OverlapsWith(ip net.IP) bool {
	if ip.IsUnspecified() && len(t) > 0 {
		return true
	}
	_, ok := t.Route(ip)
	return ok
}

// Route returns the object associated with destination ip.
//
// This can either be an entry matching argument ip exactly, or a zero IP
// address.
func (t IPTable) Route(ip net.IP) (interface{}, bool) {
	if v, ok := t[getZeroString(ip)]; ok {
		return v, true
	}
	if v, ok := t[ip.String()]; ok {
		return v, true
	}
	return nil, false
}

func getZeroString(ip net.IP) string {
	if ip.To4() != nil {
		return "0.0.0.0"
	} else {
		return "::"
	}
}

// UDPPortAllocator attempts to find a free port between a min port and a max port in
// an allocation table. Attempts wrap around when they reach max port.
//
// If no port is available, the allocation function panics.
type UDPPortAllocator struct {
	minPort  int
	maxPort  int
	nextPort int
}

// NewUDPPortAllocator returns an allocation. The function panics if min > max, or if
// min or max is not a valid port number.
func NewUDPPortAllocator(min, max int) *UDPPortAllocator {
	if min <= 0 {
		panic(fmt.Sprintf("bad min port value %d", min))
	}
	if min > max {
		panic(fmt.Sprintf("min port must be less than maxport, but %d > %d", min, max))
	}
	if max >= (1 << 16) {
		panic(fmt.Sprintf("max port cannot exceed %d (was %d)", (1<<16)-1, max))
	}
	return &UDPPortAllocator{
		minPort:  min,
		maxPort:  max,
		nextPort: min,
	}
}

// Allocate returns the next available port for the IP address. It will panic
// if it runs out of ports.
func (a *UDPPortAllocator) Allocate(ip net.IP, t *UDPPortTable) (int, error) {
	for i := a.minPort; i < a.maxPort+1; i++ {
		candidate := &net.UDPAddr{
			IP:   ip,
			Port: a.nextPort,
		}
		a.nextPort++
		if a.nextPort == a.maxPort+1 {
			a.nextPort = a.minPort
		}
		if !t.overlapsWith(candidate) {
			return candidate.Port, nil
		}
	}
	return 0, common.NewBasicError(ErrNoPorts, nil)
}
