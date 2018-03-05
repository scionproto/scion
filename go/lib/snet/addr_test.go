// Copyright 2017 ETH Zurich
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

package snet

import (
	"fmt"
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
)

func Test_Addr_String(t *testing.T) {
	ia, _ := addr.IAFromString("1-20")
	host4 := addr.HostFromIP(net.IPv4(1, 2, 3, 4))
	host6 := addr.HostFromIP(net.ParseIP("2001::1"))
	tests := []struct {
		address *Addr
		result  string
	}{
		{address: &Addr{IA: ia, Host: host4, L4Port: 10000},
			result: "1-20,[1.2.3.4]:10000"},
		{address: &Addr{IA: ia, Host: host6, L4Port: 20000},
			result: "1-20,[2001::1]:20000"},
	}
	Convey("Method String", t, func() {
		for _, test := range tests {
			Convey(fmt.Sprintf("given address object %v", test.address), func() {
				s := test.address.String()
				SoMsg("String should match", s, ShouldResemble, test.result)
			})
		}
	})
}

func Test_AddrFromString(t *testing.T) {
	tests := []struct {
		address string
		isError bool
		ia      string
		host    string
		port    uint16
	}{
		{address: "foo", isError: true},
		{address: "5-", isError: true},
		{address: "2-20,[", isError: true},
		{address: "5-14,[]:", isError: true},
		{address: "40-1,[]:19", isError: true},
		{address: "1-1,[]:13,[f", isError: true},
		{address: "1-20,[abc]:12", isError: true},
		{address: "1-2]:14,[1.2.3.4]", isError: true},
		{address: "1-1,[1.2.3.4]:70000", isError: true},
		{address: "", isError: true},
		{address: "1-1,[1.2.3.4]:80",
			ia:   "1-1",
			host: "1.2.3.4",
			port: 80},
		{address: "1-1,[1.2.3.4]",
			ia:   "1-1",
			host: "1.2.3.4",
			port: 0},
		{address: "50-50,[1.1.1.1]:5",
			ia:   "50-50",
			host: "1.1.1.1",
			port: 5},
		{address: "1-2,[::1]:60000",
			ia:   "1-2",
			host: "::1",
			port: 60000},
	}
	Convey("Function AddrFromString", t, func() {
		for _, test := range tests {
			Convey(fmt.Sprintf("given address %s", test.address), func() {
				a, err := AddrFromString(test.address)
				if test.isError {
					SoMsg("error", err, ShouldNotBeNil)
				} else {
					SoMsg("error", err, ShouldBeNil)
					SoMsg("ia", a.IA.String(), ShouldResemble, test.ia)
					SoMsg("host", a.Host.String(), ShouldResemble, test.host)
					SoMsg("port", a.L4Port, ShouldEqual, test.port)
				}
			})
		}
	})
}
