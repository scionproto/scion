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

package pathmgr

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/addr"
)

func TestRevTable(t *testing.T) {
	Convey("Create new revocation table", t, func() {
		rt := newRevTable()
		SoMsg("revocation table", rt, ShouldNotEqual, nil)

		Convey("Add path set for 1-19 -> 2-25", func() {
			aps1 := NewAppPathSet(paths["1-19.2-25"])
			rt.updatePathSet(aps1)
			SoMsg("revocation table size", len(rt.m), ShouldEqual, 12)

			Convey("Revoke non-existing UIFID 1-18#42", func() {
				ia, _ := addr.IAFromString("1-18")
				uifid := UIFIDFromValues(ia, 42)
				rt.revoke(uifid)
				SoMsg("revocation table size", len(rt.m), ShouldEqual, 12)
			})

			Convey("Revoke existing UIFID 2-25#74", func() {
				ia, _ := addr.IAFromString("2-25")
				uifid := UIFIDFromValues(ia, 74)
				rt.revoke(uifid)
				SoMsg("revocation table size", len(rt.m), ShouldEqual, 0)
				// Revoking from RevTable also deletes from aps
				SoMsg("aps len", len(aps1), ShouldEqual, 0)
			})

			Convey("Add path set for 1-10 -> 1-18", func() {
				aps2 := NewAppPathSet(paths["1-10.1-18"])
				rt.updatePathSet(aps2)
				SoMsg("revocation table size", len(rt.m), ShouldEqual, 18)

				Convey("Revoke UIFID that is member of 1 out of 2 path sets", func() {
					ia, _ := addr.IAFromString("2-21")
					uifid := UIFIDFromValues(ia, 97)
					rt.revoke(uifid)
					SoMsg("revocation table size", len(rt.m), ShouldEqual, 8)
					SoMsg("aps 1-19.2-25 size", len(aps1), ShouldEqual, 0)
					SoMsg("aps 1-10.1-18 size", len(aps2), ShouldEqual, 1)
				})

				Convey("Revoke UIFID that is member of both path sets", func() {
					ia, _ := addr.IAFromString("1-19")
					uifid := UIFIDFromValues(ia, 60)
					rt.revoke(uifid)
					SoMsg("revocation table size", len(rt.m), ShouldEqual, 0)
					SoMsg("aps 1-19.2-25 size", len(aps1), ShouldEqual, 0)
					SoMsg("aps 1-10.1-18 size", len(aps2), ShouldEqual, 0)
				})
			})
		})

		Convey("Add all paths", func() {
			m := make(map[string]AppPathSet)
			for id, path := range paths {
				m[id] = NewAppPathSet(path)
				rt.updatePathSet(m[id])
			}

			Convey("Revoking 1-14<->2-23", func() {
				expected := map[string]int{
					"1-19.2-25": 1, "1-10.1-18": 1, "2-24.1-17": 1, "2-22.1-16": 1,
					"1-18.2-25": 1, "2-21.2-26": 1, "1-11.2-23": 1, "1-13.1-18": 1}
				ia, _ := addr.IAFromString("1-14")
				uifid := UIFIDFromValues(ia, 91)
				rt.revoke(uifid)
				for srcdst, ap := range m {
					SoMsg(fmt.Sprintf("paths remaining for %v", srcdst), len(ap),
						ShouldEqual, expected[srcdst])
				}
			})

			Convey("Revoking 1-16<->1-15", func() {
				expected := map[string]int{
					"1-19.2-25": 1, "1-10.1-18": 0, "2-24.1-17": 1, "2-22.1-16": 1,
					"1-18.2-25": 1, "2-21.2-26": 1, "1-11.2-23": 1, "1-13.1-18": 1}
				ia, _ := addr.IAFromString("1-15")
				uifid := UIFIDFromValues(ia, 35)
				rt.revoke(uifid)
				for srcdst, ap := range m {
					SoMsg(fmt.Sprintf("paths remaining for %v", srcdst), len(ap),
						ShouldEqual, expected[srcdst])
				}
			})

			Convey("Revoking 1-16<->1-15, 1-11<->2-21", func() {
				expected := map[string]int{
					"1-19.2-25": 0, "1-10.1-18": 0, "2-24.1-17": 1, "2-22.1-16": 1,
					"1-18.2-25": 1, "2-21.2-26": 1, "1-11.2-23": 0, "1-13.1-18": 1}
				ia, _ := addr.IAFromString("1-15")
				uifid := UIFIDFromValues(ia, 35)
				rt.revoke(uifid)
				ia, _ = addr.IAFromString("2-21")
				uifid = UIFIDFromValues(ia, 97)
				rt.revoke(uifid)
				for srcdst, ap := range m {
					SoMsg(fmt.Sprintf("paths remaining for %v", srcdst), len(ap),
						ShouldEqual, expected[srcdst])
				}
			})

		})
	})
}
