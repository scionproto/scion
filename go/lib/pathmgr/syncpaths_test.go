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

	"github.com/scionproto/scion/go/lib/spath/spathmeta"
)

func TestSyncPathsTimestamp(t *testing.T) {
	Convey("Create SyncPaths object", t, func() {
		before := time.Now()
		sp := NewSyncPaths()
		after := time.Now()
		data := sp.Load()
		SoMsg("timestamp", data.ModifyTime, ShouldHappenOnOrBetween, before, after)
		SoMsg("timestamp", data.RefreshTime, ShouldHappenOnOrBetween, before, after)

		Convey("Call store again without changing anything", func() {
			beforeStore := time.Now()
			sp.update(spathmeta.AppPathSet(nil))
			afterStore := time.Now()
			data := sp.Load()
			Convey("Modify timestamp should not change", func() {
				SoMsg("timestamp", data.ModifyTime, ShouldHappenOnOrBetween, before, after)
			})
			Convey("Refresh timestamp should change", func() {
				SoMsg("timestamp", data.RefreshTime,
					ShouldHappenOnOrBetween, beforeStore, afterStore)
			})
		})

		Convey("Update must not modify snapshot", func() {
			data := sp.Load()
			snap := *data
			sp.update(spathmeta.AppPathSet(nil))
			Convey("Modify timestamp should not change", func() {
				SoMsg("timestamp", data.ModifyTime, ShouldResemble, snap.ModifyTime)
			})
			Convey("Refresh timestamp should not change", func() {
				SoMsg("timestamp", data.RefreshTime, ShouldResemble, snap.RefreshTime)
			})
		})

		Convey("Modifying snapshot must not affect other snapshots", func() {
			data := sp.Load()
			snap := *data
			other := sp.Load()
			other.ModifyTime = time.Unix(0, 0)
			other.RefreshTime = time.Unix(0, 0)
			Convey("Modify timestamp should not change", func() {
				SoMsg("timestamp", data.ModifyTime, ShouldResemble, snap.ModifyTime)
			})
			Convey("Refresh timestamp should not change", func() {
				SoMsg("timestamp", data.RefreshTime, ShouldResemble, snap.RefreshTime)
			})
		})
	})
}
