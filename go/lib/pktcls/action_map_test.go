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

package pktcls

import (
	"encoding/json"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/pathmgr"
)

func TestActionMap(t *testing.T) {
	Convey("Compile path predicates", t, func() {
		pp, err := pathmgr.NewPathPredicate("1-11#18,1-11#87")
		SoMsg("err", err, ShouldBeNil)
		SoMsg("pp", pp, ShouldNotBeNil)
		Convey("Create action map", func() {
			am := NewActionMap()
			Convey("Add element actionA", func() {
				actionA := NewActionFilterPaths("actionA", pp)
				err := am.Add(actionA)
				SoMsg("err", err, ShouldBeNil)
				Convey("Retrieve actionA should return the action", func() {
					action, err := am.Get("actionA")
					SoMsg("err", err, ShouldBeNil)
					SoMsg("action", action, ShouldResemble, actionA)
				})
				Convey("Retrieve actionB should return error", func() {
					_, err := am.Get("actionB")
					SoMsg("err", err, ShouldNotBeNil)
				})
				Convey("Add actionA again should return error", func() {
					err := am.Add(NewActionFilterPaths("actionA", pp))
					SoMsg("err", err, ShouldNotBeNil)
				})
				Convey("Remove actionB should return error", func() {
					err := am.Remove("actionB")
					SoMsg("err", err, ShouldNotBeNil)
				})
				Convey("Remove actionA should work", func() {
					err := am.Remove("actionA")
					SoMsg("err", err, ShouldBeNil)
				})
			})
		})
	})
}

func TestMarshalJSONActions(t *testing.T) {
	Convey("Initialize path predicates", t, func() {
		ppA, err := pathmgr.NewPathPredicate("1-11#18,1-11#87")
		SoMsg("ppA err", err, ShouldBeNil)
		SoMsg("ppA", ppA, ShouldNotBeNil)
		ppB, err := pathmgr.NewPathPredicate("2-0#0")
		SoMsg("ppB err", err, ShouldBeNil)
		SoMsg("ppB", ppB, ShouldNotBeNil)
		Convey("Create action map", func() {
			actionMap := NewActionMap()
			actionMap.Add(NewActionFilterPaths("GoThrough1-11", ppA))
			actionMap.Add(NewActionFilterPaths("GoThrough2", ppB))
			Convey("Marshal JSON", func() {
				enc, err := json.MarshalIndent(actionMap, "", "    ")
				SoMsg("err", err, ShouldBeNil)
				Convey("Unmarshal back", func() {
					amu := NewActionMap()
					err := json.Unmarshal(enc, &amu)
					SoMsg("err", err, ShouldBeNil)
					Convey("Unmarshaled action-map should be the same as the initial one", func() {
						So(amu, ShouldResemble, actionMap)
					})
				})
			})
		})
	})
}
