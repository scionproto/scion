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

package sciond

import (
	"flag"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/addr"
	. "github.com/netsec-ethz/scion/go/lib/sciond"
	//log "github.com/inconshreveable/log15"
)

var (
	integration = flag.Bool("integration", false, "run integration tests")
)

func IAFromString(s string) *addr.ISD_AS {
	a, _ := addr.IAFromString(s)
	return a
}

func TestSCIONDAPI(t *testing.T) {
	flag.Parse()
	if *integration {
		Convey("SCIOND integration tests", t, func() {
			conn, err := Connect("/run/shm/sciond/sd1-12.sock")
			So(err, ShouldBeNil)

			Convey("AS queries", func() {
				asTests := []struct {
					Message string
					Query   *addr.ISD_AS
				}{
					{"Query for AS 1-12", IAFromString("1-12")},
					{"Query for AS 2-21", IAFromString("2-21")},
					// NOTE(scrye): AS query below for non-existent AS does not cause an error.
					// SCIOND replies that it is a non-core AS.
					{"Query for AS 3-300", IAFromString("3-300")},
				}

				for _, tc := range asTests {
					Convey(tc.Message, func() {
						_, err := conn.ASInfo(tc.Query)
						So(err, ShouldBeNil)
					})
				}
			})

			Convey("Interface queries", func() {
				ifTests := []struct {
					Message   string
					Query     []uint64
					ExtraTest func(*IFInfoReply)
				}{
					{"Query for all AS 1-12 IFIDs", []uint64{}, func(info *IFInfoReply) {
						So(len(info.Entries), ShouldEqual, 4)
					}},
				}

				for _, tc := range ifTests {
					Convey(tc.Message, func() {
						info, err := conn.IFInfo(tc.Query)
						So(err, ShouldBeNil)
						if err != nil {
							return
						}
						tc.ExtraTest(info)
					})
				}
			})

			Convey("Service queries", func() {
				svcTests := []struct {
					Message string
					Query   []ServiceType
				}{
					{"Query for Beacon Servers", []ServiceType{SvcBS}},
					{"Query for Path Servers", []ServiceType{SvcPS}},
					{"Query for Certificate Servers", []ServiceType{SvcCS}},
					// NOTE(scrye): the below causes SCIOND to crash
					//{"Query for Border Routers", []ServiceType{SvcBR}},
					{"Query for SIBRA", []ServiceType{SvcSB}},
					{"Query for BS and CS", []ServiceType{SvcBS, SvcCS}},
					// NOTE(scrye): the below causes SCIOND to crash
					//{"Query for all services", []ServiceType{}},
				}

				for _, tc := range svcTests {
					Convey(tc.Message, func() {
						_, err := conn.SVCInfo(tc.Query)
						So(err, ShouldBeNil)
					})
				}
			})
		})
	} else {
		Convey("SCIOND integration test skipped (integration flag not enabled)", t, func() {})
	}
}
