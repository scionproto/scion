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
	"sort"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestSVCTableEmpty(t *testing.T) {
	address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 10080}
	value := "test value"
	Convey("Given an empty SVCTable", t, func() {
		table := NewSVCTable()
		Convey("Anycast to nil address, not found", func() {
			retValues := table.Lookup(addr.SvcCS, nil)
			So(retValues, ShouldBeEmpty)
		})
		Convey("Anycast to some IPv4 address, not found", func() {
			retValues := table.Lookup(addr.SvcCS, net.IP{10, 2, 3, 4})
			So(retValues, ShouldBeEmpty)
		})
		Convey("Multicast to some IPv4 address, not found", func() {
			retValues := table.Lookup(addr.SvcCS.Multicast(), nil)
			So(retValues, ShouldBeEmpty)
		})
		Convey("Registering nil address fails", func() {
			reference, err := table.Register(addr.SvcCS, nil, value)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("ref", reference, ShouldBeNil)
		})
		Convey("Registering IPv4 zero address fails", func() {
			zeroAddress := &net.UDPAddr{
				IP:   net.IPv4zero,
				Port: address.Port,
			}
			reference, err := table.Register(addr.SvcCS, zeroAddress, value)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("ref", reference, ShouldBeNil)
		})
		Convey("Registering IPv6 zero address fails", func() {
			zeroAddress := &net.UDPAddr{
				IP:   net.IPv6zero,
				Port: address.Port,
			}
			reference, err := table.Register(addr.SvcCS, zeroAddress, value)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("ref", reference, ShouldBeNil)
		})
		Convey("Registering port zero fails", func() {
			address := &net.UDPAddr{
				IP: address.IP,
			}
			reference, err := table.Register(addr.SvcCS, address, value)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("ref", reference, ShouldBeNil)
		})
		Convey("Registering SvcNone fails", func() {
			reference, err := table.Register(addr.SvcNone, address, value)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("ref", reference, ShouldBeNil)
		})
		Convey("Adding an address succeeds", func() {
			reference, err := table.Register(addr.SvcCS, address, value)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("ref", reference, ShouldNotBeNil)
		})
	})
}

func TestSVCTableOneItem(t *testing.T) {
	address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 10080}
	sameIpDiffPortAddress := &net.UDPAddr{IP: address.IP, Port: address.Port + 1}
	diffIpSamePortAddress := &net.UDPAddr{IP: net.IP{10, 5, 6, 7}, Port: address.Port}
	value := "test value"
	otherValue := "other test value"
	Convey("Given a table with one address", t, func() {
		table := NewSVCTable()
		reference, err := table.Register(addr.SvcCS, address, value)
		xtest.FailOnErr(t, err)
		Convey("anycasting to nil finds the entry", func() {
			// XXX(scrye): This is a workaround s.t. a simple overlay socket
			// that does not return IP-header information can still be used to
			// deliver to SVC addresses. Once IP-header information is passed
			// into the app, searching for nil should not return an entry.
			retValues := table.Lookup(addr.SvcCS, nil)
			SoMsg("len", len(retValues), ShouldEqual, 1)
		})
		Convey("multicasting to nil finds the entry", func() {
			// XXX(scrye): this is the same workaround as above
			retValues := table.Lookup(addr.SvcCS.Multicast(), nil)
			SoMsg("values", retValues, ShouldResemble, []interface{}{value})
		})
		Convey("anycasting to a different IP does not find the entry", func() {
			retValues := table.Lookup(addr.SvcCS, diffIpSamePortAddress.IP)
			So(retValues, ShouldBeEmpty)
		})
		Convey("anycasting to a different SVC does not find the entry", func() {
			retValues := table.Lookup(addr.SvcPS, address.IP)
			So(retValues, ShouldBeEmpty)
		})
		Convey("anycasting to the same SVC and IP finds the entry", func() {
			retValues := table.Lookup(addr.SvcCS, address.IP)
			SoMsg("values", retValues, ShouldResemble, []interface{}{value})
		})
		Convey("multicasting to the same SVC and IP finds the entry", func() {
			retValues := table.Lookup(addr.SvcCS.Multicast(), nil)
			SoMsg("values", retValues, ShouldResemble, []interface{}{value})
		})
		Convey("Registering the same address and different port succeeds", func() {
			ref, err := table.Register(addr.SvcCS, sameIpDiffPortAddress, value)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("ref", ref, ShouldNotBeNil)
		})
		Convey("Registering the same address and same port fails", func() {
			ref, err := table.Register(addr.SvcCS, address, value)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("ref", ref, ShouldBeNil)
		})
		Convey("Freeing the reference yields nil on anycast", func() {
			reference.Free()
			retValues := table.Lookup(addr.SvcCS, nil)
			So(retValues, ShouldBeEmpty)
			Convey("And double free panics", func() {
				So(reference.Free, ShouldPanic)
			})
			Convey("And adding the same address again now succeeds", func() {
				_, err := table.Register(addr.SvcCS, address, value)
				SoMsg("err", err, ShouldBeNil)
			})
		})
		Convey("Adding a second address, anycasting to first one returns correct value", func() {
			_, err := table.Register(addr.SvcCS, diffIpSamePortAddress, otherValue)
			SoMsg("err", err, ShouldBeNil)
			retValues := table.Lookup(addr.SvcCS, address.IP)
			SoMsg("values", retValues, ShouldResemble, []interface{}{value})
		})
	})

}

func TestSVCTableTwoItems(t *testing.T) {
	address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 10080}
	sameIpDiffPortAddress := &net.UDPAddr{IP: address.IP, Port: address.Port + 1}
	value := "test value"
	otherValue := "other test value"
	Convey("Given a table with two ports for the same address and service", t, func() {
		table := NewSVCTable()
		_, err := table.Register(addr.SvcCS, address, value)
		xtest.FailOnErr(t, err)
		_, err = table.Register(addr.SvcCS, sameIpDiffPortAddress, otherValue)
		xtest.FailOnErr(t, err)
		Convey("The anycasts will cycle between the values", func() {
			retValues := table.Lookup(addr.SvcCS, address.IP)
			SoMsg("values", retValues, ShouldResemble, []interface{}{value})
			otherRetValue := table.Lookup(addr.SvcCS, address.IP)
			SoMsg("second values", otherRetValue, ShouldResemble, []interface{}{otherValue})
		})
		Convey("A multicast will return both values", func() {
			retValues := table.Lookup(addr.SvcCS.Multicast(), address.IP)
			SoMsg("len", len(retValues), ShouldEqual, 2)
		})
	})
}

func TestSVCTableMulticastTwoAddresses(t *testing.T) {
	address := &net.UDPAddr{IP: net.IP{10, 2, 3, 4}, Port: 10080}
	diffAddress := &net.UDPAddr{IP: net.IP{10, 5, 6, 7}, Port: address.Port}
	value := "test value"
	otherValue := "other test value"
	Convey("Given a table with two addresses and the same service", t, func() {
		table := NewSVCTable()
		_, err := table.Register(addr.SvcCS, address, value)
		xtest.FailOnErr(t, err)
		_, err = table.Register(addr.SvcCS, diffAddress, otherValue)
		xtest.FailOnErr(t, err)
		Convey("A multicast will return both values", func() {
			retValues := table.Lookup(addr.SvcCS.Multicast(), address.IP)
			sort.Slice(retValues, func(i, j int) bool {
				return retValues[i].(string) < retValues[j].(string)
			})
			So(retValues, ShouldResemble, []interface{}{otherValue, value})
		})
	})
}

func TestSVCTableStress(t *testing.T) {
	registrationCount := 1000
	Convey("Generate many random registrations, then free all", t, func() {
		table := NewSVCTable()
		references := runRandomRegistrations(registrationCount, table)
		for _, ref := range references {
			ref.Free()
		}
		Convey("then generate some more, and free again", func() {
			references := runRandomRegistrations(registrationCount, table)
			for _, ref := range references {
				ref.Free()
			}
			Convey("table should be empty", func() {
				So(table.String(), ShouldEqual, "map[]")
			})
		})
	})

}

func TestSVCTableFree(t *testing.T) {
	Convey("", t, func() {
		Convey("Given a table with three entries on the same IP", func() {
			ip := net.IP{10, 2, 3, 4}
			table := NewSVCTable()
			addressOne := &net.UDPAddr{IP: ip, Port: 10080}
			_, err := table.Register(addr.SvcCS, addressOne, "1")
			xtest.FailOnErr(t, err)
			addressTwo := &net.UDPAddr{IP: ip, Port: 10081}
			refTwo, err := table.Register(addr.SvcCS, addressTwo, "2")
			xtest.FailOnErr(t, err)
			addressThree := &net.UDPAddr{IP: ip, Port: 10082}
			_, err = table.Register(addr.SvcCS, addressThree, "3")
			xtest.FailOnErr(t, err)
			Convey("if the second address is removed", func() {
				refTwo.Free()
				Convey("anycasting cycles between addresses one and three", func() {
					retValuesOne := table.Lookup(addr.SvcCS, ip)
					SoMsg("retValuesOne", retValuesOne, ShouldResemble, []interface{}{"1"})
					retValueThree := table.Lookup(addr.SvcCS, ip)
					SoMsg("retValuesThree", retValueThree, ShouldResemble, []interface{}{"3"})
				})
			})
		})
	})
}

func runRandomRegistrations(count int, table SVCTable) []Reference {
	var references []Reference
	for i := 0; i < count; i++ {
		ref, err := table.Register(addr.SvcCS, getRandomUDPAddress(), getRandomValue())
		if err == nil {
			references = append(references, ref)
		}
	}
	return references
}
