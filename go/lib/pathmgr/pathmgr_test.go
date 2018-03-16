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
	"time"

	log "github.com/inconshreveable/log15"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

func TestQuery(t *testing.T) {
	Convey("Query, we have 0 paths and SCIOND is asked again, receive 1 path", t, func() {
		g := graph.NewDefaultGraph()
		pm := NewPR(t, g, 250, 250, 100)
		srcIA := MustParseIA("1-10")
		dstIA := MustParseIA("1-16")

		aps := pm.Query(srcIA, dstIA)
		SoMsg("aps len", len(aps), ShouldEqual, 1)
		Convey("Query immediately, same path is read from cache", func() {
			aps := pm.Query(srcIA, dstIA)
			SoMsg("aps len", len(aps), ShouldEqual, 1)
			SoMsg("path", getPathStrings(aps), ShouldContain,
				"[1-10#1019 1-19#1910 1-19#1916 1-16#1619]")
		})
		Convey("Wait 200ms for paths to expire, then query and get new paths", func() {
			// Add new path between 1-10 and 1-16
			g.AddLink("1-10", 101902, "1-19", 191002)
			// Wait for two seconds to guarantee that the pathmgr refreshes the paths
			<-time.After(200 * time.Millisecond)
			aps := pm.Query(srcIA, dstIA)
			SoMsg("aps len", len(aps), ShouldEqual, 2)
			SoMsg("path #1", getPathStrings(aps), ShouldContain,
				"[1-10#1019 1-19#1910 1-19#1916 1-16#1619]")
			SoMsg("path #2", getPathStrings(aps), ShouldContain,
				"[1-10#101902 1-19#191002 1-19#1916 1-16#1619]")
		})
	})
}

func TestQueryFilter(t *testing.T) {
	Convey("Query with filter, only one path should remain", t, func() {
		g := graph.NewDefaultGraph()
		pm := NewPR(t, g, 0, 0, 0)
		srcIA := MustParseIA("1-10")
		dstIA := MustParseIA("1-16")

		pp, err := NewPathPredicate("1-19#0")
		SoMsg("err", err, ShouldBeNil)
		SoMsg("pp", pp, ShouldNotBeNil)

		aps := pm.QueryFilter(srcIA, dstIA, pp)
		SoMsg("aps len", len(aps), ShouldEqual, 1)
		SoMsg("path", getPathStrings(aps), ShouldContain,
			"[1-10#1019 1-19#1910 1-19#1916 1-16#1619]")
	})
}

func TestRegister(t *testing.T) {
	Convey("Register for path, receive 0 responses", t, func() {
		g := graph.NewDefaultGraph()
		// Remove link between 1-19 and 1-16 so that the initial path set is
		// nil
		g.RemoveLink(1019)
		pm := NewPR(t, g, 100, 100, 100)
		srcIA := MustParseIA("1-10")
		dstIA := MustParseIA("1-16")

		sp, err := pm.Watch(srcIA, dstIA)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("aps", len(sp.Load().APS), ShouldEqual, 0)

		Convey("Wait 200ms, the APS should contain fresh paths", func() {
			// Re-add the link between 1-19 and 1-16; the path manager will
			// update APS behind the scenes (after a normal refire of one
			// second), so it should contain the path after 4 seconds.
			g.AddLink("1-10", 1019, "1-19", 1910)
			<-time.After(200 * time.Millisecond)
			SoMsg("aps", len(sp.Load().APS), ShouldEqual, 1)
			SoMsg("path", getPathStrings(sp.Load().APS), ShouldContain,
				"[1-10#1019 1-19#1910 1-19#1916 1-16#1619]")
		})
	})
}

func TestRegisterFilter(t *testing.T) {
	Convey("Register filter 1-19#1910", t, func() {
		g := graph.NewDefaultGraph()
		pm := NewPR(t, g, 500, 500, 1000)
		srcIA := MustParseIA("1-10")
		dstIA := MustParseIA("1-16")

		pp, err := NewPathPredicate("1-19#1910")
		SoMsg("pp", pp, ShouldNotBeNil)
		SoMsg("err", err, ShouldBeNil)

		sp, err := pm.WatchFilter(srcIA, dstIA, pp)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("len aps", len(sp.Load().APS), ShouldEqual, 1)
		SoMsg("path", getPathStrings(sp.Load().APS), ShouldContain,
			"[1-10#1019 1-19#1910 1-19#1916 1-16#1619]")
	})
}

func TestRevoke(t *testing.T) {
	Convey("Populate cache via Query, Watch, WatchFilter for different destinations", t, func() {
		g := graph.NewDefaultGraph()
		pm := NewPR(t, g, 60, 60, 60)
		// Query: 1-10 -> 1-16
		querySrc := MustParseIA("1-10")
		queryDst := MustParseIA("1-16")
		// Watch/WatchFilter: 1-18 -> 2-22
		watchSrc := MustParseIA("1-18")
		watchDst := MustParseIA("2-22")

		aps := pm.Query(querySrc, queryDst)
		apsCheckPaths("path", aps,
			"[1-10#1019 1-19#1910 1-19#1916 1-16#1619]")

		sp, err := pm.Watch(watchSrc, watchDst)
		SoMsg("watch: ee", err, ShouldBeNil)
		apsCheckPaths("watch", sp.Load().APS,
			"[1-18#1815 1-15#1518 1-15#1512 1-12#1215 1-12#1222 2-22#2212]")

		pp, err := NewPathPredicate("1-15#1518")
		SoMsg("err predicate", err, ShouldBeNil)
		spf, err := pm.WatchFilter(watchSrc, watchDst, pp)
		SoMsg("watch filter: err", err, ShouldBeNil)
		apsCheckPaths("watch filter", spf.Load().APS,
			"[1-18#1815 1-15#1518 1-15#1512 1-12#1215 1-12#1222 2-22#2212]")

		Convey("Revoke a path that's not part of any path set", func() {
			g.RemoveLink(1311)
			pm.cache.revoke(uifidFromValues(MustParseIA("1-13"), 1311))
			aps := pm.Query(querySrc, queryDst)
			apsCheckPaths("path", aps,
				"[1-10#1019 1-19#1910 1-19#1916 1-16#1619]")
			apsCheckPaths("watch", sp.Load().APS,
				"[1-18#1815 1-15#1518 1-15#1512 1-12#1215 1-12#1222 2-22#2212]")
			apsCheckPaths("watch filter", spf.Load().APS,
				"[1-18#1815 1-15#1518 1-15#1512 1-12#1215 1-12#1222 2-22#2212]")
		})
		Convey("Revoke a path that's in Query, but not in Watch/WatchFilter path sets", func() {
			// Disconnect #1019
			// Note that the revoke below only invalidates the cache and
			// does not inform sciond. This means that the path manager
			// reaches 0 paths after the revocation, thus forcing a requery
			// to sciond behind the scenes, which gets back the same path.
			g.RemoveLink(1019)
			pm.cache.revoke(uifidFromValues(MustParseIA("1-10"), 1019))
			aps := pm.Query(querySrc, queryDst)
			apsCheckPaths("path", aps)
			apsCheckPaths("watch", sp.Load().APS,
				"[1-18#1815 1-15#1518 1-15#1512 1-12#1215 1-12#1222 2-22#2212]")
			apsCheckPaths("watch filter", spf.Load().APS,
				"[1-18#1815 1-15#1518 1-15#1512 1-12#1215 1-12#1222 2-22#2212]")
		})
		Convey("Revoke a path that's in Watch and WatchFilter, but not in Query", func() {
			// Disconnect #1815
			// The revoke below only invalidates the cache. Because watches
			// do not requery sciond automatically (like the previous
			// test), they will be left with 0 paths.
			g.RemoveLink(1815)
			pm.cache.revoke(uifidFromValues(watchSrc, 1815))
			apsCheckPaths("path", aps,
				"[1-10#1019 1-19#1910 1-19#1916 1-16#1619]")
			apsCheckPaths("watch", sp.Load().APS)
			apsCheckPaths("watch filter", spf.Load().APS)
		})
	})
}

func NewPR(t *testing.T, g *graph.Graph, normalRefire, errorRefire, maxAge int) *PR {
	t.Helper()

	pm, err := New(
		sciond.NewMockService(g),
		&Timers{
			NormalRefire: time.Duration(normalRefire) * time.Millisecond,
			ErrorRefire:  time.Duration(errorRefire) * time.Millisecond,
			MaxAge:       time.Duration(maxAge) * time.Millisecond,
		},
		log.Root(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return pm
}

func getPathStrings(aps AppPathSet) []string {
	var ss []string
	for _, v := range aps {
		ss = append(ss, fmt.Sprintf("%v", v.Entry.Path.Interfaces))
	}
	return ss
}

func apsCheckPaths(desc string, aps AppPathSet, expValues ...string) {
	SoMsg(fmt.Sprintf("%s: len", desc), len(aps), ShouldEqual, len(expValues))
	for i, value := range expValues {
		SoMsg(fmt.Sprintf("%s: path %d", desc, i), getPathStrings(aps), ShouldContain, value)
	}
}
