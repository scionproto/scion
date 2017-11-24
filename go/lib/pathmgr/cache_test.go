// Copyright 2017 Audrius Meskauskas with all possible permissions granted
// to ETH Zurich and Anapaya Systems
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
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

// First key-value pair
var src1 addr.ISD_AS
var dst1 addr.ISD_AS
var appPath1 AppPath
var path1 AppPathSet

// Second key-value pair
var src2 addr.ISD_AS
var dst2 addr.ISD_AS
var appPath2 AppPath
var path2 AppPathSet

// Points to nothing
var srcNone addr.ISD_AS
var dstNone addr.ISD_AS

// Create cache with expected initial content
func setup() *cache {
	var cache = newCache(time.Hour)

	src1 = addr.ISD_AS{I: 1, A: 2}
	dst1 = addr.ISD_AS{I: 3, A: 4}
	appPath1 = AppPath{Entry: &sciond.PathReplyEntry{Path: sciond.FwdPathMeta{
		Interfaces: []sciond.PathInterface{
			{RawIsdas: src1.IAInt(), IfID: 11}, {RawIsdas: dst1.IAInt(), IfID: 12},
		}}, HostInfo: sciond.HostInfo{Port: 7003}}}
	path1 = AppPathSet{appPath1.Key(): &appPath1}

	// Second key-value pair
	src2 = addr.ISD_AS{I: 5, A: 6}
	dst2 = addr.ISD_AS{I: 7, A: 8}
	appPath2 = AppPath{Entry: &sciond.PathReplyEntry{Path: sciond.FwdPathMeta{
		Interfaces: []sciond.PathInterface{
			{RawIsdas: src2.IAInt(), IfID: 11}, {RawIsdas: dst2.IAInt(), IfID: 12},
		}}, HostInfo: sciond.HostInfo{Port: 7002}}}
	path2 = AppPathSet{appPath2.Key(): &appPath2}

	// Points to nothing
	srcNone = addr.ISD_AS{I: 50, A: 60}
	dstNone = addr.ISD_AS{I: 70, A: 80}

	cache.update(&src1, &dst1, path1)
	cache.update(&src2, &dst2, path2)
	return cache
}

func Test_GetAPSExisting(t *testing.T) {
	var cache = setup()

	Convey("Existing entries can be found", t, func() {
		pathSet, found := cache.getAPS(&src1, &dst1)
		So(found, ShouldBeTrue)
		So(pathSet, ShouldEqual, path1)

		pathSet, found = cache.getAPS(&src2, &dst2)
		So(found, ShouldBeTrue)
		So(pathSet, ShouldEqual, path2)
	})
}

func Test_Remove(t *testing.T) {
	var cache = setup()
	cache.remove(&src1, &dst1, &appPath1)

	Convey("Existing entries still must be found", t, func() {
		pathSet, found := cache.getAPS(&src2, &dst2)
		So(found, ShouldBeTrue)
		So(pathSet, ShouldEqual, path2)
	})

	Convey("Removed entries must not found", t, func() {
		pathSet, found := cache.getAPS(&src1, &dst1)
		So(found, ShouldBeFalse)
		So(pathSet, ShouldBeNil)
	})
}

func Test_GetAPSNonExistent(t *testing.T) {
	var cache = setup()

	Convey("Non existent entries must be missing", t, func() {
		pathSet, found := cache.getAPS(&srcNone, &dstNone)
		So(found, ShouldBeFalse)
		So(pathSet, ShouldBeNil)

		pathSet, found = cache.getAPS(&src1, &dstNone)
		So(found, ShouldBeFalse)
		So(pathSet, ShouldBeNil)

		pathSet, found = cache.getAPS(&srcNone, &dst1)
		So(found, ShouldBeFalse)
		So(pathSet, ShouldBeNil)
	})
}

func Test_Update(t *testing.T) {
	var cache = setup()

	// Replace path (was path1)
	cache.update(&src1, &dst1, path2)

	// Add, there was not path between these two nodes
	cache.update(&src2, &dst1, path1)

	Convey("Entry must be replaced", t, func() {
		pathSet, found := cache.getAPS(&src1, &dst1)
		So(found, ShouldBeTrue)
		So(pathSet, ShouldEqual, path2)
	})

	Convey("Entry must be added", t, func() {
		pathSet, found := cache.getAPS(&src2, &dst1)
		So(found, ShouldBeTrue)
		So(pathSet, ShouldEqual, path1)
	})
}

func Test_RevokeCacheEntry(t *testing.T) {
	var cache = setup()

	revokeThis := uifid{IA("7-77"), 7777}
	cache.revTable.m[revokeThis] = path2
	cache.revoke(revokeThis)

	Convey("Non relevant entry must still persist", t, func() {
		pathSet, found := cache.getAPS(&src1, &dst1)
		So(found, ShouldBeTrue)
		So(pathSet, ShouldEqual, path1)
	})

	Convey("Entry must be revoked", t, func() {
		pathSet, found := cache.getAPS(&src2, &dst2)
		So(found, ShouldBeFalse)
		So(pathSet, ShouldBeNil)
	})
}

func Test_WatchMultiple(t *testing.T) {
	var cache = setup()

	// Watch twice
	cache.watch(&src1, &dst1, nil)
	cache.watch(&src1, &dst1, nil)

	Convey("Watch must be removed twice to consider unwatched", t, func() {
		So(cache.isWatched(&src1, &dst1), ShouldBeTrue)

		cache.removeWatch(&src1, &dst1, nil)
		So(cache.isWatched(&src1, &dst1), ShouldBeTrue)

		cache.removeWatch(&src1, &dst1, nil)
		So(cache.isWatched(&src1, &dst1), ShouldBeFalse)
	})
}

func Test_WatchWithFilter(t *testing.T) {
	var cache = setup()

	predicate, _ := NewPathPredicate("0-0#123")

	// Watch twice the same entry, and twice with predicate
	cache.watch(&src1, &dst1, nil)

	cache.watch(&src1, &dst1, predicate)
	cache.watch(&src1, &dst1, predicate)

	Convey("Watch must be removed twice to consider unwatched", t, func() {
		So(cache.isWatched(&src1, &dst1), ShouldBeTrue)

		// Remove first
		cache.removeWatch(&src1, &dst1, nil)
		So(cache.isWatched(&src1, &dst1), ShouldBeTrue)

		// Remove second time - no effect, already none
		cache.removeWatch(&src1, &dst1, nil)
		So(cache.isWatched(&src1, &dst1), ShouldBeTrue)

		// Remove predicate now
		cache.removeWatch(&src1, &dst1, predicate)
		So(cache.isWatched(&src1, &dst1), ShouldBeTrue) // 1 remaining
		cache.removeWatch(&src1, &dst1, predicate)
		So(cache.isWatched(&src1, &dst1), ShouldBeFalse) // 0 remaining
	})
}

func Test_IsWatched(t *testing.T) {
	var cache = setup()

	// Watch on existing
	cache.watch(&src1, &dst1, nil)
	// Watch new
	cache.watch(&src1, &dst2, nil)

	Convey("Unwatched entries must not be reported", t, func() {
		So(cache.isWatched(&srcNone, &dstNone), ShouldBeFalse)
		So(cache.isWatched(&src2, &dst1), ShouldBeFalse)
	})

	Convey("Watched entries must be reported as such", t, func() {
		So(cache.isWatched(&src1, &dst2), ShouldBeTrue)
	})
}

func Test_GetWatch(t *testing.T) {
	var cache = setup()

	Convey("Watched entry must be reported", t, func() {

		// Add, check if present
		cache.watch(&src1, &dst1, nil)
		So(cache.isWatched(&src1, &dst1), ShouldBeTrue)

		pf, found := cache.getWatch(&src1, &dst1, nil)
		So(found, ShouldBeTrue)

		stored := pf.value.Load().(*SyncPathsData)
		So(stored.APS, ShouldEqual, path1)

		// Remove now, check no longer present
		cache.removeWatch(&src1, &dst1, nil)

		So(cache.isWatched(&src1, &dst1), ShouldBeFalse)
		pf, found = cache.getWatch(&src1, &dst1, nil)
		So(found, ShouldBeFalse)
		So(pf, ShouldBeNil)
	})
}
