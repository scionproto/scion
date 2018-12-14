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
	// Anycast returns the entry associated with svc and ip.
	//
	// If no entry is found, the second return value is false.
	//
	// If multiple entries exist (this can happen with different port numbers),
	// one of the entries is returned in round-robin fashion.
	Anycast(svc addr.HostSVC, ip net.IP) (interface{}, bool)
	// String returns the entire table in string form.
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

func (t *svcTable) Anycast(svc addr.HostSVC, ip net.IP) (interface{}, bool) {
	ipTable, ok := t.m[svc]
	if !ok {
		return nil, false
	}
	portList, ok := ipTable[ip.String()]
	if !ok {
		return nil, false
	}
	return portList.Get(), true
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
