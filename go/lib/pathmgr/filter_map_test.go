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
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/addr"
)

func TestFilterMap(t *testing.T) {
	Convey("Compile path predicates", t, func() {
		ppA, err := NewPathPredicate("2-21#69")
		SoMsg("err A", err, ShouldBeNil)
		ppB, err := NewPathPredicate("1-12#0,2-22#0")
		SoMsg("err B", err, ShouldBeNil)
		fm := make(filterMap)
		src := &addr.ISD_AS{I: 1, A: 10}
		dst := &addr.ISD_AS{I: 2, A: 20}

		// All paths in an AppPathSet are usually between the same source and
		// destination. For testing purposes we'll not impose this restriction
		// here.
		aps := make(AppPathSet)
		pathsByID := make(map[string]*AppPath)
		for id, path := range paths {
			ap := &AppPath{Entry: &path.Entries[0]}
			pathsByID[id] = ap
			aps[ap.Key()] = ap
		}

		Convey("Get absent src-dst pair 1-10.2-20, predicateA", func() {
			sp, ok := fm.get(src, dst, ppA)
			SoMsg("ok", ok, ShouldBeFalse)
			SoMsg("sp", sp, ShouldBeNil)
		})

		Convey("Set path predicate A for 1-10.2-20", func() {
			before := time.Now()
			sp := fm.set(src, dst, ppA)
			after := time.Now()
			SoMsg("sp", sp, ShouldNotBeNil)
			snapshot := sp.Load()
			SoMsg("sp pathset", snapshot.APS, ShouldResemble, NewSyncPaths().Load().APS)
			SoMsg("sp mod time", snapshot.ModifyTime, ShouldHappenBetween, before, after)
			SoMsg("sp refresh time", snapshot.RefreshTime, ShouldHappenBetween, before, after)
			Convey("Get filter object for 1-10.2-20, predicate A", func() {
				sp, ok := fm.get(src, dst, ppA)
				SoMsg("ok", ok, ShouldBeTrue)
				SoMsg("sp", sp.Load().APS, ShouldResemble, NewSyncPaths().Load().APS)
			})

			Convey("Get filter object for 1-10.2-20, missing predicate B", func() {
				sp, ok := fm.get(src, dst, ppB)
				SoMsg("ok", ok, ShouldBeFalse)
				SoMsg("sp", sp, ShouldBeNil)
			})

			Convey("Set path predicate B for 1-20.2-20", func() {
				before := time.Now()
				sp := fm.set(src, dst, ppB)
				after := time.Now()
				SoMsg("sp", sp, ShouldNotBeNil)
				snapshot := sp.Load()
				SoMsg("sp pathset", snapshot.APS, ShouldResemble, NewSyncPaths().Load().APS)
				SoMsg("sp mod time", snapshot.ModifyTime, ShouldHappenBetween, before, after)
				SoMsg("sp refresh time", snapshot.RefreshTime, ShouldHappenBetween, before, after)

				Convey("Get filter object for 1-20.2-20, predicate B", func() {
					sp, ok := fm.get(src, dst, ppB)
					SoMsg("ok", ok, ShouldBeTrue)
					SoMsg("sp", sp, ShouldNotBeNil)
					snapshot := sp.Load()
					SoMsg("sp pathset", snapshot.APS, ShouldResemble, NewSyncPaths().Load().APS)
					SoMsg("sp mod time", snapshot.ModifyTime, ShouldHappenBetween, before, after)
					SoMsg("sp refresh time", snapshot.RefreshTime, ShouldHappenBetween, before, after)
				})

				Convey("Update paths", func() {
					before := time.Now()
					fm.update(src, dst, aps)
					after := time.Now()
					Convey("Get filter object for 1-10.2-20, predicate A", func() {
						sp, ok := fm.get(src, dst, ppA)
						SoMsg("ok", ok, ShouldBeTrue)
						SoMsg("sp", sp, ShouldNotBeNil)
						snapshot := sp.Load()
						SoMsg("sp pathset", snapshot.APS, ShouldResemble,
							AppPathSet{
								pathsByID["1-19.2-25"].Key(): pathsByID["1-19.2-25"],
								pathsByID["1-18.2-25"].Key(): pathsByID["1-18.2-25"],
								pathsByID["2-21.2-26"].Key(): pathsByID["2-21.2-26"],
								pathsByID["1-11.2-23"].Key(): pathsByID["1-11.2-23"],
							})
						SoMsg("sp mod time", snapshot.ModifyTime, ShouldHappenBetween, before, after)
						SoMsg("sp refresh time", snapshot.RefreshTime, ShouldHappenBetween, before, after)
					})

					Convey("Get filter object for 1-10.2-20, predicate B", func() {
						sp, ok := fm.get(src, dst, ppB)
						SoMsg("ok", ok, ShouldBeTrue)
						SoMsg("sp", sp, ShouldNotBeNil)
						snapshot := sp.Load()
						SoMsg("sp pathset", snapshot.APS, ShouldResemble,
							AppPathSet{
								pathsByID["1-18.2-25"].Key(): pathsByID["1-18.2-25"],
							})
						SoMsg("sp mod time", snapshot.ModifyTime, ShouldHappenBetween, before, after)
						SoMsg("sp refresh time", snapshot.RefreshTime, ShouldHappenBetween, before, after)
					})

					Convey("Update paths again with a different set, thus changing SyncPaths", func() {
						// Delete the last four paths
						delete(aps, pathsByID["1-18.2-25"].Key())
						delete(aps, pathsByID["2-21.2-26"].Key())
						delete(aps, pathsByID["1-11.2-23"].Key())
						delete(aps, pathsByID["1-13.1-18"].Key())
						before := time.Now()
						fm.update(src, dst, aps)
						after := time.Now()
						Convey("Get filter object for 1-10.2-20, predicate A", func() {
							sp, ok := fm.get(src, dst, ppA)
							SoMsg("ok", ok, ShouldBeTrue)
							SoMsg("sp", sp, ShouldNotBeNil)
							snapshot := sp.Load()
							SoMsg("sp pathset", snapshot.APS, ShouldResemble,
								AppPathSet{
									pathsByID["1-19.2-25"].Key(): pathsByID["1-19.2-25"],
								})
							SoMsg("sp mod time", snapshot.ModifyTime, ShouldHappenBetween, before, after)
							SoMsg("sp refresh time", snapshot.RefreshTime, ShouldHappenBetween, before, after)
						})

						Convey("Get filter object for 1-10.2-20, predicate B", func() {
							sp, ok := fm.get(src, dst, ppB)
							SoMsg("ok", ok, ShouldBeTrue)
							SoMsg("sp", sp, ShouldNotBeNil)
							snapshot := sp.Load()
							SoMsg("sp pathset", snapshot.APS, ShouldResemble, NewSyncPaths().Load().APS)
							SoMsg("sp mod time", snapshot.ModifyTime, ShouldHappenBetween, before, after)
							SoMsg("sp refresh time", snapshot.RefreshTime, ShouldHappenBetween, before, after)
						})
					})

					Convey("Update paths with the same set, thus leaving SyncPaths unchanged", func() {
						before := time.Now()
						fm.update(src, dst, aps)
						after := time.Now()
						Convey("Get filter object for 1-10.2-20, predicate A", func() {
							sp, ok := fm.get(src, dst, ppA)
							SoMsg("ok", ok, ShouldBeTrue)
							SoMsg("sp", sp, ShouldNotBeNil)
							snapshot := sp.Load()
							SoMsg("sp pathset", snapshot.APS, ShouldResemble,
								AppPathSet{
									pathsByID["1-19.2-25"].Key(): pathsByID["1-19.2-25"],
									pathsByID["1-18.2-25"].Key(): pathsByID["1-18.2-25"],
									pathsByID["2-21.2-26"].Key(): pathsByID["2-21.2-26"],
									pathsByID["1-11.2-23"].Key(): pathsByID["1-11.2-23"],
								})
							SoMsg("sp mod time", snapshot.ModifyTime, ShouldHappenBefore, before)
							SoMsg("sp refresh time", snapshot.RefreshTime, ShouldHappenBetween, before, after)
						})

						Convey("Get filter object for 1-10.2-20, predicate B", func() {
							sp, ok := fm.get(src, dst, ppB)
							SoMsg("ok", ok, ShouldBeTrue)
							SoMsg("sp", sp, ShouldNotBeNil)
							snapshot := sp.Load()
							SoMsg("sp pathset", snapshot.APS, ShouldResemble,
								AppPathSet{
									pathsByID["1-18.2-25"].Key(): pathsByID["1-18.2-25"],
								})
							SoMsg("sp mod time", snapshot.ModifyTime, ShouldHappenBefore, before)
							SoMsg("sp refresh time", snapshot.RefreshTime, ShouldHappenBetween, before, after)
						})
					})
				})
			})
		})
	})
}
