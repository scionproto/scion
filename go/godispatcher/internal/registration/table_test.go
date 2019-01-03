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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestRegister(t *testing.T) {
	public := &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 80}
	bind := net.IP{10, 2, 3, 4}
	value := "test value"
	Convey("Given a table", t, func() {
		table := NewTable(minPort, maxPort)
		Convey("Initial size is 0", func() {
			So(table.Size(), ShouldEqual, 0)
		})
		Convey("Register with no public address -> failure", func() {
			ref, err := table.Register(nil, nil, addr.SvcNone, value)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("ref", ref, ShouldBeNil)
		})
		Convey("Register with zero public IPv4 address -> success", func() {
			public := &net.UDPAddr{
				IP:   net.IPv4zero,
				Port: 80,
			}
			ref, err := table.Register(public, nil, addr.SvcNone, value)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("ref", ref, ShouldNotBeNil)
		})
		Convey("Register with zero public IPv6 address -> success", func() {
			public := &net.UDPAddr{
				IP:   net.IPv6zero,
				Port: 80,
			}
			ref, err := table.Register(public, nil, addr.SvcNone, value)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("ref", ref, ShouldNotBeNil)
		})
		Convey("Register with public address with port, no bind, no svc -> success", func() {
			ref, err := table.Register(public, nil, addr.SvcNone, value)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("ref", ref, ShouldNotBeNil)
		})
		Convey("Register with public address without port, no bind, no svc -> success", func() {
			public := &net.UDPAddr{
				IP: public.IP,
			}
			ref, err := table.Register(public, nil, addr.SvcNone, value)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("ref", ref, ShouldNotBeNil)
		})
		Convey("Register with public address, bind, no svc -> failure", func() {
			ref, err := table.Register(public, bind, addr.SvcNone, value)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("ref", ref, ShouldBeNil)
		})
		Convey("Register with public address, no bind, svc -> success", func() {
			ref, err := table.Register(public, nil, addr.SvcPS, value)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("ref", ref, ShouldNotBeNil)
		})
		Convey("Register with zero bind IPv4 address -> failure", func() {
			ref, err := table.Register(public, net.IPv4zero, addr.SvcCS, value)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("ref", ref, ShouldBeNil)
		})
		Convey("Register with zero bind IPv6 address -> failure", func() {
			ref, err := table.Register(public, net.IPv6zero, addr.SvcCS, value)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("ref", ref, ShouldBeNil)
		})
		Convey("Register with public address, bind, svc -> success", func() {
			ref, err := table.Register(public, bind, addr.SvcCS, value)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("ref", ref, ShouldNotBeNil)
		})
	})
}

func TestRegisterOnlyPublic(t *testing.T) {
	public := &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 80}
	value := "test value"
	Convey("Given a table with a public address registration", t, func() {
		table := NewTable(minPort, maxPort)
		ref, err := table.Register(public, nil, addr.SvcNone, value)
		xtest.FailOnErr(t, err)
		Convey("Initial size is 1", func() {
			So(table.Size(), ShouldEqual, 1)
		})
		Convey("Lookup is successful", func() {
			retValue, ok := table.LookupPublic(public)
			SoMsg("ok", ok, ShouldBeTrue)
			SoMsg("value", retValue, ShouldEqual, value)
		})
		Convey("Free reference, size is 0", func() {
			ref.Free()
			So(table.Size(), ShouldEqual, 0)
			Convey("Free same reference again, panic", func() {
				So(ref.Free, ShouldPanic)
			})
			Convey("Lookup now fails", func() {
				retValue, ok := table.LookupPublic(public)
				SoMsg("ok", ok, ShouldBeFalse)
				SoMsg("value", retValue, ShouldBeNil)
			})
		})
		Convey("Register same address returns error", func() {
			ref, err := table.Register(public, nil, addr.SvcNone, value)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("ref", ref, ShouldBeNil)
		})
		Convey("Register 0.0.0.0, error due to overlap", func() {
			public := &net.UDPAddr{IP: net.IPv4zero, Port: 80}
			ref, err := table.Register(public, nil, addr.SvcNone, value)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("ref", ref, ShouldBeNil)
		})
		Convey("Register ::, success", func() {
			public := &net.UDPAddr{IP: net.IPv6zero, Port: 80}
			ref, err := table.Register(public, nil, addr.SvcNone, value)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("ref", ref, ShouldNotBeNil)
		})
	})
}

func TestRegisterPublicAndSVC(t *testing.T) {
	public := &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 80}
	value := "test value"
	Convey("Given a table with a public address registration", t, func() {
		table := NewTable(minPort, maxPort)
		_, err := table.Register(public, nil, addr.SvcCS, value)
		xtest.FailOnErr(t, err)
		Convey("Initial size is 1", func() {
			So(table.Size(), ShouldEqual, 1)
		})
		Convey("Public lookup is successful", func() {
			retValue, ok := table.LookupPublic(public)
			SoMsg("ok", ok, ShouldBeTrue)
			SoMsg("value", retValue, ShouldEqual, value)
		})
		Convey("SVC lookup is successful (bind inherits from public)", func() {
			retValue, ok := table.LookupService(addr.SvcCS, public.IP)
			SoMsg("ok", ok, ShouldBeTrue)
			SoMsg("value", retValue, ShouldEqual, value)
		})
	})
}

func TestRegisterWithBind(t *testing.T) {
	public := &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 80}
	bind := net.IP{10, 2, 3, 4}
	value := "test value"
	Convey("Given a table with a bind address registration", t, func() {
		table := NewTable(minPort, maxPort)
		ref, err := table.Register(public, bind, addr.SvcCS, value)
		xtest.FailOnErr(t, err)
		Convey("Initial size is 1", func() {
			So(table.Size(), ShouldEqual, 1)
		})
		Convey("Public lookup is successful", func() {
			retValue, ok := table.LookupPublic(public)
			SoMsg("ok", ok, ShouldBeTrue)
			SoMsg("value", retValue, ShouldEqual, value)
		})
		Convey("SVC lookup is successful", func() {
			retValue, ok := table.LookupService(addr.SvcCS, bind)
			SoMsg("ok", ok, ShouldBeTrue)
			SoMsg("value", retValue, ShouldEqual, value)
		})
		Convey("Bind lookup on different svc fails", func() {
			retValue, ok := table.LookupService(addr.SvcBS, bind)
			SoMsg("ok", ok, ShouldBeFalse)
			SoMsg("value", retValue, ShouldBeNil)
		})
		Convey("Colliding binds return error, and public port is released", func() {
			otherPublic := &net.UDPAddr{IP: net.IP{192, 0, 2, 2}, Port: 80}
			_, err := table.Register(otherPublic, bind, addr.SvcCS, value)
			SoMsg("first err", err, ShouldNotBeNil)
			SoMsg("size", table.Size(), ShouldEqual, 1)
			_, err = table.Register(otherPublic, nil, addr.SvcNone, value)
			SoMsg("second err", err, ShouldBeNil)
		})
		Convey("Freeing the entry allows for reregistration", func() {
			ref.Free()
			_, err := table.Register(public, bind, addr.SvcCS, value)
			So(err, ShouldBeNil)
		})
	})
}
