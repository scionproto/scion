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

package registration_test

import (
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/godispatcher/registration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestIATable(t *testing.T) {
	Convey("Given a table with one entry", t, func() {
		table := registration.NewIATable(minPort, maxPort)
		public := &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 80}
		value := "test value"
		ia := xtest.MustParseIA("1-ff00:0:1")
		Convey("if the entry is only public", func() {
			ref, err := table.Register(ia, public, nil, addr.SvcNone, value)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("ref", ref, ShouldNotBeNil)
			Convey("lookups for the same AS", func() {
				Convey("work correctly for public", func() {
					retValue, ok := table.LookupPublic(ia, public)
					SoMsg("ok", ok, ShouldBeTrue)
					SoMsg("value", retValue, ShouldEqual, value)
				})
				Convey("work correctly for SVC", func() {
					retValue, ok := table.LookupService(ia, addr.SvcCS, net.IP{192, 0, 2, 1})
					SoMsg("ok", ok, ShouldBeFalse)
					SoMsg("value", retValue, ShouldBeNil)
				})
			})
			Convey("lookups for a different AS", func() {
				otherIA := xtest.MustParseIA("1-ff00:0:2")
				Convey("work correctly for public", func() {
					retValue, ok := table.LookupPublic(otherIA, public)
					SoMsg("ok", ok, ShouldBeFalse)
					SoMsg("value", retValue, ShouldBeNil)
				})
				Convey("work correctly for SVC", func() {
					retValue, ok := table.LookupService(otherIA, addr.SvcCS, net.IP{192, 0, 2, 1})
					SoMsg("ok", ok, ShouldBeFalse)
					SoMsg("value", retValue, ShouldBeNil)
				})
			})
			Convey("free", func() {
				ref.Free()
				Convey("double free panics", func() {
					So(ref.Free, ShouldPanic)
				})
			})
		})
		Convey("if the entry is public and svc", func() {
			ref, err := table.Register(ia, public, nil, addr.SvcCS, value)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("ref", ref, ShouldNotBeNil)
			Convey("lookups for the same AS", func() {
				Convey("work correctly for public", func() {
					retValue, ok := table.LookupPublic(ia, public)
					SoMsg("ok", ok, ShouldBeTrue)
					SoMsg("value", retValue, ShouldEqual, value)
				})
				Convey("work correctly for SVC", func() {
					retValue, ok := table.LookupService(ia, addr.SvcCS, net.IP{192, 0, 2, 1})
					SoMsg("ok", ok, ShouldBeTrue)
					SoMsg("value", retValue, ShouldEqual, value)
				})
			})
		})
	})
}

func TestIATableRegister(t *testing.T) {
	Convey("Given an empty table", t, func() {
		table := registration.NewIATable(minPort, maxPort)
		public := &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 80}
		value := "test value"
		Convey("ISD zero is error", func() {
			ref, err := table.Register(addr.IA{I: 0, A: 1}, public, nil, addr.SvcNone, value)
			xtest.SoMsgErrorStr("err", err, registration.ErrBadISD)
			SoMsg("ref", ref, ShouldBeNil)
		})
		Convey("AS zero is error", func() {
			ref, err := table.Register(addr.IA{I: 1, A: 0}, public, nil, addr.SvcNone, value)
			xtest.SoMsgErrorStr("err", err, registration.ErrBadAS)
			SoMsg("ref", ref, ShouldBeNil)
		})
		Convey("for a good AS number", func() {
			ia := xtest.MustParseIA("1-ff00:0:1")
			Convey("already registered ports will cause error", func() {
				_, err := table.Register(ia, public, nil, addr.SvcNone, value)
				xtest.FailOnErr(t, err)
				ref, err := table.Register(ia, public, nil, addr.SvcNone, value)
				SoMsg("err", err, ShouldNotBeNil)
				SoMsg("ref", ref, ShouldBeNil)
			})
			Convey("good ports will return success", func() {
				ref, err := table.Register(ia, public, nil, addr.SvcNone, value)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("ref", ref, ShouldNotBeNil)
			})
		})
	})
}
