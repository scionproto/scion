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

	log "github.com/inconshreveable/log15"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/sciond/graph"
)

func TestQuery(t *testing.T) {
	Convey("Create path manager (path set max age = 1 second)", t, func() {
		g := graph.NewFromDescription(graph.DefaultGraphDescription)
		pm, err := New(
			sciond.NewMockService(g),
			&Timers{
				NormalRefire: 5 * time.Second,
				ErrorRefire:  5 * time.Second,
				MaxAge:       time.Second,
			},
			log.Root(),
		)
		SoMsg("pm", pm, ShouldNotBeNil)
		SoMsg("err", err, ShouldBeNil)

		Convey("Query, we have 0 paths and SCIOND is asked again, receive 1 path", func() {
			srcIA := MustParseIA("1-10")
			dstIA := MustParseIA("1-16")
			aps := pm.Query(srcIA, dstIA)
			SoMsg("aps len", len(aps), ShouldEqual, 1)
			Convey("Query immediately, same path is read from cache", func() {
				aps := pm.Query(srcIA, dstIA)
				SoMsg("aps len", len(aps), ShouldEqual, 1)
			})
			Convey("Wait 2 seconds for paths to expire, then query and get new paths", func() {
				// Add new path between 1-10 and 1-16
				g.Connect("1-10", 101902, "1-19", 191002)
				// Wait for two seconds to guarantee that the pathmgr refreshes the paths
				<-time.After(2 * time.Second)
				aps := pm.Query(srcIA, dstIA)
				SoMsg("aps len", len(aps), ShouldEqual, 2)
			})
		})
	})
}

func TestQueryFilter(t *testing.T) {
	Convey("Create path manager", t, func() {
		g := graph.NewFromDescription(graph.DefaultGraphDescription)
		pm, err := New(sciond.NewMockService(g), &Timers{}, log.Root())
		SoMsg("pm", pm, ShouldNotBeNil)
		SoMsg("err", err, ShouldBeNil)

		Convey("Query with filter, only one path should remain", func() {
			srcIA := MustParseIA("1-10")
			dstIA := MustParseIA("1-16")

			pp, err := NewPathPredicate("1-19#0")
			SoMsg("err", err, ShouldBeNil)
			SoMsg("pp", pp, ShouldNotBeNil)

			aps := pm.QueryFilter(srcIA, dstIA, pp)
			SoMsg("aps len", len(aps), ShouldEqual, 1)
		})
	})
}

func TestRegister(t *testing.T) {
	Convey("Create path manager", t, func() {
		g := graph.NewFromDescription(graph.DefaultGraphDescription)
		// Remove link between 1-19 and 1-16 so that the initial path set is
		// nil
		g.Disconnect(1019)

		pm, err := New(
			sciond.NewMockService(g),
			&Timers{
				NormalRefire: time.Second,
				ErrorRefire:  time.Second,
				MaxAge:       time.Second,
			},
			log.Root(),
		)
		SoMsg("pm", pm, ShouldNotBeNil)
		SoMsg("err", err, ShouldBeNil)

		Convey("Register for path, receive 0 responses", func() {
			srcIA := MustParseIA("1-10")
			dstIA := MustParseIA("1-16")

			sp, err := pm.Watch(srcIA, dstIA)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("aps", len(sp.Load().APS), ShouldEqual, 0)

			Convey("Wait 5 seconds, the APS should contain fresh paths", func() {
				// Readd the link between 1-19 and 1-16; the path manager will
				// update APS behind the scenes (after a normal refire of one
				// second), so it should contain the path after 4 seconds.
				g.Connect("1-10", 1019, "1-19", 1910)
				<-time.After(4 * time.Second)
				SoMsg("aps", len(sp.Load().APS), ShouldEqual, 1)
			})
		})
	})
}

func TestRegisterFilter(t *testing.T) {
	Convey("Create path manager", t, func() {
		g := graph.NewFromDescription(graph.DefaultGraphDescription)

		pm, err := New(
			sciond.NewMockService(g),
			&Timers{
				NormalRefire: time.Second,
				ErrorRefire:  time.Second,
				MaxAge:       time.Second,
			},
			log.Root(),
		)
		SoMsg("pm", pm, ShouldNotBeNil)
		SoMsg("err", err, ShouldBeNil)

		Convey("Register filter 1-19#1910", func() {
			srcIA := MustParseIA("1-10")
			dstIA := MustParseIA("1-16")

			pp, err := NewPathPredicate("1-19#1910")
			SoMsg("pp", pp, ShouldNotBeNil)
			SoMsg("err", err, ShouldBeNil)

			sp, err := pm.WatchFilter(srcIA, dstIA, pp)
			SoMsg("err", err, ShouldBeNil)
			SoMsg("len aps", len(sp.Load().APS), ShouldEqual, 1)
		})
	})
}

func TestRevoke(t *testing.T) {
	Convey("Create path manager", t, func() {
		g := graph.NewFromDescription(graph.DefaultGraphDescription)

		pm, err := New(
			sciond.NewMockService(g),
			&Timers{
				NormalRefire: time.Minute,
				ErrorRefire:  time.Minute,
				MaxAge:       time.Minute,
			},
			log.Root(),
		)
		SoMsg("pm", pm, ShouldNotBeNil)
		SoMsg("err", err, ShouldBeNil)

		Convey("Populate cache via Query, Watch, WatchFilter for different destinations", func() {
			// Query: 1-10 -> 1-16
			querySrc := MustParseIA("1-10")
			queryDst := MustParseIA("1-16")
			// Watch/WatchFilter: 1-18 -> 2-22
			watchSrc := MustParseIA("1-18")
			watchDst := MustParseIA("2-22")

			aps := pm.Query(querySrc, queryDst)
			SoMsg("len(aps)", len(aps), ShouldEqual, 1)

			sp, err := pm.Watch(watchSrc, watchDst)
			SoMsg("err watch", err, ShouldBeNil)
			SoMsg("len(aps) watch", len(sp.Load().APS), ShouldEqual, 1)

			pp, err := NewPathPredicate("1-15#1518")
			SoMsg("err predicate", err, ShouldBeNil)
			spf, err := pm.WatchFilter(watchSrc, watchDst, pp)
			SoMsg("err watch filter", err, ShouldBeNil)
			SoMsg("len(aps) watch filter", len(spf.Load().APS), ShouldEqual, 1)

			Convey("Revoke a path that's not part of any path set", func() {
				g.Disconnect(1311)
				aps := pm.Query(querySrc, queryDst)
				SoMsg("len(aps)", len(aps), ShouldEqual, 1)
			})
			Convey("Revoke a path that's in Query, but not in Watch/WatchFilter path sets", func() {
				// Disconnect #1619
				// Note that the revoke below only invalidates the cache and
				// does not inform sciond. This means that the path manager
				// reaches 0 paths after the revocation, thus forcing a requery
				// to sciond behind the scenes, which gets back the same path.
				pm.cache.revoke(uifidFromValues(MustParseIA("1-10"), 1019))
				aps := pm.Query(querySrc, queryDst)
				SoMsg("len(aps)", len(aps), ShouldEqual, 1)
			})
			Convey("Revoke a path that's in Watch and WatchFilter, but not in Query", func() {
				// Disconnect #1815
				// The revoke below only invalidates the cache. Because watches
				// do not requery sciond automatically (like the previous
				// test), they will be left with 0 paths.
				pm.cache.revoke(uifidFromValues(watchSrc, 1815))
				SoMsg("len(aps) watch", len(sp.Load().APS), ShouldEqual, 0)
				SoMsg("len(aps) watch filter", len(spf.Load().APS), ShouldEqual, 0)
			})
		})
	})
}
