// Copyright 2019 ETH Zurich
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
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/xtest"
)

func TestSCMPEmptyTable(t *testing.T) {
	Convey("Given an empty table", t, func() {
		table := NewSCMPTable()

		Convey("Lookup for an id fails", func() {
			value, ok := table.Lookup(42)
			SoMsg("ok", ok, ShouldBeFalse)
			SoMsg("value", value, ShouldBeNil)
		})
		Convey("Adding an item succeeds", func() {
			value := "test value"
			err := table.Register(42, value)
			So(err, ShouldBeNil)
		})
		Convey("Adding an item with nil value fails", func() {
			err := table.Register(42, nil)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestSCMPTableWithOneItem(t *testing.T) {
	Convey("Given a table with one element", t, func() {
		table := NewSCMPTable()
		value := "test value"
		err := table.Register(42, value)
		xtest.FailOnErr(t, err)
		Convey("Lookup for the id succeeds", func() {
			retValue, ok := table.Lookup(42)
			SoMsg("ok", ok, ShouldBeTrue)
			SoMsg("value", retValue, ShouldEqual, value)
		})
		Convey("Adding the same id fails", func() {
			err := table.Register(42, "some other value")
			So(err, ShouldNotBeNil)
		})
		Convey("After removing the ID, lookup fails", func() {
			table.Remove(42)
			value, ok := table.Lookup(42)
			SoMsg("ok", ok, ShouldBeFalse)
			SoMsg("value", value, ShouldBeNil)
		})
	})
}
