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
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

var docIPv6AddressStr = "2001:db8::1"
var docIPv6Address = net.ParseIP(docIPv6AddressStr)

var minPort = 1024
var maxPort = 65535

func testUDPTableWithPorts(v4, v6 map[int]IPTable) *UDPPortTable {
	if v4 == nil {
		v4 = map[int]IPTable{}
	}
	if v6 == nil {
		v6 = map[int]IPTable{}
	}
	return NewUDPPortTableFromMap(minPort, maxPort, v4, v6)
}

func TestUDPPortTableLookup(t *testing.T) {
	value := "test value"
	Convey("", t, func() {
		Convey("Given a non-zero IPv4 address", func() {
			address := &net.UDPAddr{IP: net.IP{10, 1, 2, 3}, Port: 10080}
			Convey("Lookup on an empty table returns nil", func() {
				table := NewUDPPortTable(minPort, maxPort)
				retValue, ok := table.Lookup(address)
				SoMsg("value", retValue, ShouldBeNil)
				SoMsg("ok", ok, ShouldBeFalse)
			})
			Convey("Lookup on table with non-matching entries returns nil", func() {
				table := testUDPTableWithPorts(map[int]IPTable{
					10080: {"10.4.5.6": value}}, nil)
				retValue, ok := table.Lookup(address)
				SoMsg("value", retValue, ShouldBeNil)
				SoMsg("ok", ok, ShouldBeFalse)
			})
			Convey("Lookup on table with exact match returns value", func() {
				table := testUDPTableWithPorts(map[int]IPTable{
					10080: {"10.1.2.3": value}}, nil)
				retValue, ok := table.Lookup(address)
				SoMsg("value", retValue, ShouldEqual, value)
				SoMsg("ok", ok, ShouldBeTrue)
			})
			Convey("Lookup on table with matching 0.0.0.0 entry returns value", func() {
				table := testUDPTableWithPorts(map[int]IPTable{
					10080: {"0.0.0.0": value}}, nil)
				retValue, ok := table.Lookup(address)
				SoMsg("value", retValue, ShouldEqual, value)
				SoMsg("ok", ok, ShouldBeTrue)
			})
			Convey("Lookup on table with non-matching 0.0.0.0 entry returns nil", func() {
				table := testUDPTableWithPorts(map[int]IPTable{
					80: {"0.0.0.0": value}}, nil)
				retValue, ok := table.Lookup(address)
				SoMsg("value", retValue, ShouldBeNil)
				SoMsg("ok", ok, ShouldBeFalse)
			})
		})
		Convey("Lookup fails for zero IPv4 address", func() {
			table := NewUDPPortTable(minPort, maxPort)
			address := &net.UDPAddr{IP: net.IPv4zero, Port: 10080}
			retValue, ok := table.Lookup(address)
			SoMsg("value", retValue, ShouldBeNil)
			SoMsg("ok", ok, ShouldBeFalse)
		})
		Convey("Given an IPv6 address", func() {
			address := &net.UDPAddr{IP: docIPv6Address, Port: 10080}
			Convey("Lookup on table with matching entry returns value", func() {
				table := testUDPTableWithPorts(nil, map[int]IPTable{
					10080: {docIPv6AddressStr: value},
				})
				retValue, ok := table.Lookup(address)
				SoMsg("value", retValue, ShouldEqual, value)
				SoMsg("ok", ok, ShouldBeTrue)
			})
			Convey("Lookup on table with matching :: entry returns value", func() {
				table := testUDPTableWithPorts(nil, map[int]IPTable{
					10080: {"::": value},
				})
				retValue, ok := table.Lookup(address)
				SoMsg("value", retValue, ShouldEqual, value)
				SoMsg("ok", ok, ShouldBeTrue)
			})
			Convey("Lookup on table with non-matching :: entry returns nil", func() {
				table := testUDPTableWithPorts(nil, map[int]IPTable{
					80: {"::": value},
				})
				retValue, ok := table.Lookup(address)
				SoMsg("value", retValue, ShouldBeNil)
				SoMsg("ok", ok, ShouldBeFalse)
			})
		})
	})
}

func TestUDPPortTableInsert(t *testing.T) {
	value := "Test value"
	Convey("", t, func() {
		Convey("Given an empty table", func() {
			table := NewUDPPortTable(minPort, maxPort)
			Convey("Inserting an IPv4 address with a port returns a copy of the same address",
				func() {
					address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 10080}
					retAddress, err := table.Insert(address, value)
					_, lookupOk := table.Lookup(address)
					SoMsg("err", err, ShouldBeNil)
					SoMsg("address content", retAddress, ShouldResemble, address)
					SoMsg("address not same object", retAddress, ShouldNotEqual, address)
					SoMsg("lookup ok", lookupOk, ShouldBeTrue)
				})
			Convey("Inserting an IPv4 address with a 0 port returns an allocated port",
				func() {
					address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}}
					expectedAddress := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 1024}
					retAddress, err := table.Insert(address, value)
					_, lookupOk := table.Lookup(expectedAddress)
					SoMsg("err", err, ShouldBeNil)
					SoMsg("address", retAddress, ShouldResemble, expectedAddress)
					SoMsg("lookup ok", lookupOk, ShouldBeTrue)
				})
			Convey("Inserting an IPv6 address with a port returns a copy of the same address",
				func() {
					address := &net.UDPAddr{IP: docIPv6Address, Port: 10080}
					retAddress, err := table.Insert(address, value)
					_, lookupOk := table.Lookup(address)
					SoMsg("err", err, ShouldBeNil)
					SoMsg("address content", retAddress, ShouldResemble, address)
					SoMsg("address not same object", retAddress, ShouldNotEqual, address)
					SoMsg("lookup ok", lookupOk, ShouldBeTrue)
				})
			Convey("Inserting an IPv6 address with a 0 port returns an allocated port",
				func() {
					address := &net.UDPAddr{IP: docIPv6Address}
					expectedAddress := &net.UDPAddr{IP: docIPv6Address, Port: 1024}
					retAddress, err := table.Insert(address, value)
					_, lookupOk := table.Lookup(expectedAddress)
					SoMsg("err", err, ShouldBeNil)
					SoMsg("address", retAddress, ShouldResemble, expectedAddress)
					SoMsg("lookup ok", lookupOk, ShouldBeTrue)
				})
			Convey("Inserting an address without a value is not permitted", func() {
				address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 10080}
				retAddress, err := table.Insert(address, nil)
				_, lookupOk := table.Lookup(address)
				SoMsg("err", err, ShouldNotBeNil)
				SoMsg("address", retAddress, ShouldBeNil)
				SoMsg("lookup ok", lookupOk, ShouldBeFalse)
			})
			Convey("Inserting a zero IPv4 address is permitted", func() {
				address := &net.UDPAddr{IP: net.IPv4zero, Port: 10080}
				retAddress, err := table.Insert(address, value)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("address", retAddress, ShouldResemble, address)
			})
			Convey("Inserting a zero IPv6 address is permitted", func() {
				address := &net.UDPAddr{IP: net.IPv6zero, Port: 10080}
				retAddress, err := table.Insert(address, value)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("address", retAddress, ShouldResemble, address)
			})
		})
		Convey("Given a table with a zero address", func() {
			table := testUDPTableWithPorts(map[int]IPTable{
				1024: {"0.0.0.0": value}}, nil)
			Convey("A colliding allocation will return an error", func() {
				address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 1024}
				retAddress, err := table.Insert(address, value)
				SoMsg("err", err, ShouldNotBeNil)
				SoMsg("address", retAddress, ShouldBeNil)
			})
		})
		Convey("Given a table with a non-zero address", func() {
			table := testUDPTableWithPorts(map[int]IPTable{
				1024: {"10.0.0.0": value}}, nil)
			Convey("Inserting zero IPv4 address on the same port fails", func() {
				address := &net.UDPAddr{IP: net.IPv4zero, Port: 1024}
				retAddress, err := table.Insert(address, value)
				SoMsg("err", err, ShouldNotBeNil)
				SoMsg("address", retAddress, ShouldBeNil)
			})
			Convey("Inserting zero IPv6 address on the same port succeeds", func() {
				address := &net.UDPAddr{IP: net.IPv6zero, Port: 1024}
				retAddress, err := table.Insert(address, value)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("address", retAddress, ShouldResemble, address)
			})
		})
	})
}

func TestUDPPortTableRemove(t *testing.T) {
	value := "test value"
	Convey("", t, func() {
		Convey("", func() {
			table := testUDPTableWithPorts(
				map[int]IPTable{
					10080: {"10.2.3.4": value},
					10081: {"0.0.0.0": value}},
				map[int]IPTable{
					10082: {docIPv6AddressStr: value},
					10083: {"::": value}},
			)

			Convey("Remove non-zero addresses", func() {
				addrs := []*net.UDPAddr{
					{IP: net.IP{10, 2, 3, 4}, Port: 10080},
					{IP: docIPv6Address, Port: 10082},
				}
				for _, address := range addrs {
					_, lookupOk := table.Lookup(address)
					SoMsg("lookup succeeds before removing", lookupOk, ShouldBeTrue)
					table.Remove(address)
					_, lookupOk = table.Lookup(address)
					SoMsg("lookup fails after removing", lookupOk, ShouldBeFalse)
				}
			})
			Convey("Remove zero address", func() {
				addrs := map[*net.UDPAddr]net.IP{
					{IP: net.IPv4zero, Port: 10081}: {10, 1, 2, 3},
					{IP: net.IPv6zero, Port: 10083}: docIPv6Address,
				}

				for address, lookupAddress := range addrs {
					_, lookupOk := table.Lookup(&net.UDPAddr{IP: lookupAddress, Port: address.Port})
					SoMsg("lookup succeeds before removing", lookupOk, ShouldBeTrue)
					table.Remove(address)
					_, lookupOk = table.Lookup(&net.UDPAddr{IP: lookupAddress, Port: address.Port})
					SoMsg("lookup fails after removing", lookupOk, ShouldBeFalse)
				}
			})
		})
		Convey("Removing non-existent entry does not panic", func() {
			table := NewUDPPortTable(minPort, maxPort)
			address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 666}
			So(func() { table.Remove(address) }, ShouldNotPanic)
		})
	})
}

func TestUDPPortAllocator(t *testing.T) {
	address := net.IP{10, 2, 3, 4}
	value := "test value"
	Convey("", t, func() {
		Convey("Constructing an allocator with minport > maxport will panic", func() {
			So(func() { NewUDPPortAllocator(10, 4) }, ShouldPanic)
		})
		Convey("Constructing an allocator with a negative minport will panic", func() {
			So(func() { NewUDPPortAllocator(-4, 4) }, ShouldPanic)
		})
		Convey("Constructing an allocator with a minport of 0 will panic", func() {
			So(func() { NewUDPPortAllocator(0, 4) }, ShouldPanic)
		})
		Convey("Constructing an allocator with maxport > 65535 wil panic", func() {
			So(func() { NewUDPPortAllocator(1, 65536) }, ShouldPanic)
		})
		Convey("Given an allocator", func() {
			allocator := NewUDPPortAllocator(1000, 1500)
			table := NewUDPPortTable(minPort, maxPort)
			Convey("if table is empty, first allocation gives min port", func() {
				port, err := allocator.Allocate(address, table)
				SoMsg("port", port, ShouldEqual, 1000)
				SoMsg("err", err, ShouldBeNil)
			})
			Convey("if table contains used first port, first allocation gives next port", func() {
				port, err := allocator.Allocate(address, testUDPTableWithPorts(
					map[int]IPTable{
						1000: {"10.2.3.4": value},
					}, nil,
				))
				SoMsg("port", port, ShouldEqual, 1001)
				SoMsg("err", err, ShouldBeNil)
			})
			Convey("if wildcard bind uses first port, first allocation gives next port", func() {
				port, err := allocator.Allocate(address, testUDPTableWithPorts(
					map[int]IPTable{
						1000: {"0.0.0.0": value},
					}, nil,
				))
				SoMsg("port", port, ShouldEqual, 1001)
				SoMsg("err", err, ShouldBeNil)
			})
		})
		Convey("Given an allocator with few ports", func() {
			allocator := NewUDPPortAllocator(1, 3)
			Convey("if all ports are taken except max, max is chosen", func() {
				port, err := allocator.Allocate(address, testUDPTableWithPorts(
					map[int]IPTable{
						1: {"0.0.0.0": value},
						2: {"0.0.0.0": value},
					}, nil,
				))
				SoMsg("port", port, ShouldEqual, 3)
				SoMsg("err", err, ShouldBeNil)
				Convey("if first port is available, it is chosen after wrapping", func() {
					port, err := allocator.Allocate(address, testUDPTableWithPorts(
						map[int]IPTable{
							2: {"0.0.0.0": value},
							3: {"0.0.0.0": value},
						}, nil,
					))
					SoMsg("port", port, ShouldEqual, 1)
					SoMsg("err", err, ShouldBeNil)
				})
			})
			Convey("if all ports are taken, error", func() {
				table := testUDPTableWithPorts(
					map[int]IPTable{
						1: {"0.0.0.0": value},
						2: {"0.0.0.0": value},
						3: {"0.0.0.0": value},
					}, nil)
				port, err := allocator.Allocate(address, table)
				SoMsg("port", port, ShouldEqual, 0)
				SoMsg("err", err, ShouldNotBeNil)
			})
		})
		Convey("Given an allocator with IPv6 data", func() {
			v6address := net.ParseIP(docIPv6AddressStr)
			allocator := NewUDPPortAllocator(1000, 1500)
			table := testUDPTableWithPorts(nil,
				map[int]IPTable{
					1000: {docIPv6AddressStr: value},
				})
			Convey("allocation skips ports correctly for IPv6", func() {
				port, err := allocator.Allocate(v6address, table)
				SoMsg("port", port, ShouldEqual, 1001)
				SoMsg("err", err, ShouldBeNil)
			})
		})
	})
}
