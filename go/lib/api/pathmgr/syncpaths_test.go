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
)

func TestSyncPathsTimestamp(t *testing.T) {
	Convey("Create SyncPaths object", t, func() {
		before := time.Now()
		sp := NewSyncPaths()
		after := time.Now()
		data := sp.Load()
		SoMsg("timestamp", data.ModifyTime, ShouldHappenBetween, before, after)
		SoMsg("timestamp", data.RefreshTime, ShouldHappenBetween, before, after)

		Convey("Call store again without changing anything", func() {
			beforeStore := time.Now()
			sp.update(AppPathSet(nil))
			afterStore := time.Now()
			data := sp.Load()
			Convey("Modify timestamp should not change", func() {
				SoMsg("timestamp", data.ModifyTime, ShouldHappenBetween, before, after)
			})
			Convey("Refresh timestamp should change", func() {
				SoMsg("timestamp", data.RefreshTime, ShouldHappenBetween, beforeStore, afterStore)
			})
		})
	})
}
