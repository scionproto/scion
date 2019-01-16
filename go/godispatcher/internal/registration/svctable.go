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
	"container/ring"
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

// SVCTable tracks SVC registrations.
//
// Entries are hierarchical, and conceptually look like the following:
//
//  SVC CS:
//    10.2.3.4
//      :10080
//      :10081
//    192.0.2.1
//      :20000
//  SVC PS:
//    192.0.2.2
//      :20001
//    2001:db8::1
//      :30001
//      :30002
//
// Call Register to add a new entry to the table. The IP and port are taken
// from the UDP address. IP must not be zero (so binding to multiple interfaces
// is not supported), and port must not be zero.
//
// Anycasting to a local application requires the service type (e.g., CS) and
// the IP. This is because for SCION, the IP is selected remotely by the border
// router. The local dispatcher then anycasts between all local ports listening on that IP.
//
// For example, in the table above, anycasting to CS-10.2.3.4 can either go to
// entry 10.2.3.4:10080 or 10.2.3.4:10081. Anycasts are chosen in round-robin
// fashion; the round-robin distribution is not strict, and can get skewed due
// to registrations and frees.
type SVCTable interface {
	// Register adds a new entry for the select svc, IP address and port. Both
	// IPv4 and IPv6 are supported. IP addresses 0.0.0.0 and :: are not
	// supported. Port must not be 0.
	//
	// If an entry for the same svc, IP address and port exists, an error is
	// returned and the reference is nil.
	//
	// To clean up resources, call Free on the returned Reference. Calling Free
	// more than once will cause a panic.
	Register(svc addr.HostSVC, address *net.UDPAddr, value interface{}) (Reference, error)
	// Lookup returns the entries associated with svc and ip.
	//
	// If SVC is an anycast address, at most one entry is returned. The ip
	// address is used in case to narrow down the set of possible entries. If
	// multiple entries exist, one is selected arbitrarily.
	//
	// Note that nil addresses are supported for anycasts (the address is then
	// ignored), but support for this might be dropped in the future.
	//
	// If SVC is a multicast address, more than one entry can be returned. The
	// ip address is ignored in this case.
	Lookup(svc addr.HostSVC, ip net.IP) []interface{}
	String() string
}

func NewSVCTable() SVCTable {
	return newSvcTable()
}

var _ SVCTable = (*svcTable)(nil)

type svcTable struct {
	m map[addr.HostSVC]unicastIpTable
}

func newSvcTable() *svcTable {
	return &svcTable{
		m: make(map[addr.HostSVC]unicastIpTable),
	}
}

func (t *svcTable) Register(svc addr.HostSVC, address *net.UDPAddr,
	value interface{}) (Reference, error) {

	if err := validateUDPAddr(address); err != nil {
		return nil, err
	}
	if svc == addr.SvcNone {
		return nil, common.NewBasicError(ErrSvcNone, nil)
	}
	// save a copy of the address to prevent callers from later affecting table
	// state
	address = copyUDPAddr(address)

	if _, ok := t.m[svc]; !ok {
		t.m[svc] = make(unicastIpTable)
	}

	element, err := t.m[svc].insert(address, value)
	if err != nil {
		return nil, err
	}
	return &svcTableReference{
		cleanF: t.buildCleanupCallback(svc, address.IP, element),
	}, nil
}

func (t *svcTable) Lookup(svc addr.HostSVC, ip net.IP) []interface{} {
	var values []interface{}
	if svc.IsMulticast() {
		values = t.multicast(svc)
	} else {
		if v, ok := t.anycast(svc, ip); ok {
			values = []interface{}{v}
		}
	}
	return values
}

func (t *svcTable) multicast(svc addr.HostSVC) []interface{} {
	var values []interface{}
	ipTable, ok := t.m[svc.Base()]
	if !ok {
		return values
	}
	for _, v := range ipTable {
		for i := 0; i < v.Len(); i++ {
			values = append(values, v.Get())
		}
	}
	return values
}

func (t *svcTable) anycast(svc addr.HostSVC, ip net.IP) (interface{}, bool) {
	ipTable, ok := t.m[svc]
	if !ok {
		return nil, false
	}
	// XXX(scrye): This is a workaround s.t. a simple overlay socket
	// that does not return IP-header information can still be used to
	// deliver to SVC addresses. Once IP-header information is passed
	// into the app, searching for nil should not return an entry.
	var ports *portList
	if ip == nil {
		ports, ok = ipTable.any()
	} else {
		ports, ok = ipTable[ip.String()]
	}
	if !ok {
		return nil, false
	}
	return ports.Get(), true
}

func (t *svcTable) String() string {
	return fmt.Sprintf("%v", t.m)
}

func (t *svcTable) buildCleanupCallback(svc addr.HostSVC, ip net.IP, port *ring.Ring) func() {
	return func() {
		t.doCleanup(svc, ip, port)
	}
}

func (t *svcTable) doCleanup(svc addr.HostSVC, ip net.IP, port *ring.Ring) {
	ipTable := t.m[svc]
	portList := ipTable[ip.String()]
	portList.Remove(port)
	if portList.Len() == 0 {
		delete(ipTable, ip.String())
	}
	if len(ipTable) == 0 {
		delete(t.m, svc)
	}
}

func validateUDPAddr(address *net.UDPAddr) error {
	if address == nil {
		return common.NewBasicError(ErrNilAddress, nil)
	}
	if address.IP.IsUnspecified() {
		return common.NewBasicError(ErrZeroIP, nil)
	}
	if address.Port == 0 {
		return common.NewBasicError(ErrZeroPort, nil)
	}
	return nil
}

type unicastIpTable map[string]*portList

// insert adds an entry for address to the table, and returns a pointer to the
// entry.
func (t unicastIpTable) insert(address *net.UDPAddr, value interface{}) (*ring.Ring, error) {
	var list *portList
	str := address.IP.String()
	list, ok := t[str]
	if ok {
		if list.Find(address.Port) {
			return nil, common.NewBasicError(ErrOverlappingAddress, nil)
		}
	} else {
		list = newPortList()
		t[str] = list
	}
	return list.Insert(address.Port, value), nil
}

// any returns an arbitrary item from the table. The boolean return value is
// true if an entry was found, or false otherwise.
func (t unicastIpTable) any() (*portList, bool) {
	for _, v := range t {
		return v, true
	}
	return nil, false
}

var _ Reference = (*svcTableReference)(nil)

type svcTableReference struct {
	freed  bool
	cleanF func()
}

func (r *svcTableReference) Free() {
	if r.freed {
		panic("double free")
	}
	r.freed = true
	r.cleanF()
}
