// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/pktcls"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

func TestQuery(t *testing.T) {
	Convey("Query, we have 0 paths and SCIOND is asked again, receive 1 path", t, func() {
		g := graph.NewDefaultGraph()
		pm := NewPR(t, g, 250, 250, 100)
		srcIA := xtest.MustParseIA("1-ff00:0:133")
		dstIA := xtest.MustParseIA("1-ff00:0:131")

		aps := pm.Query(srcIA, dstIA)
		SoMsg("aps len", len(aps), ShouldEqual, 1)
		Convey("Query immediately, same path is read from cache", func() {
			aps := pm.Query(srcIA, dstIA)
			SoMsg("aps len", len(aps), ShouldEqual, 1)
			SoMsg("path", getPathStrings(aps), ShouldContain,
				"[1-ff00:0:133#1019 1-ff00:0:132#1910 "+
					"1-ff00:0:132#1916 1-ff00:0:131#1619]")
		})
		Convey("Wait 200ms for paths to expire, then query and get new paths", func() {
			// Add new path between 1-ff00:0:133 and 1-ff00:0:131
			g.AddLink("1-ff00:0:133", 101902, "1-ff00:0:132", 191002, false)
			// Wait for two seconds to guarantee that the pathmgr refreshes the paths
			<-time.After(200 * time.Millisecond)
			aps := pm.Query(srcIA, dstIA)
			SoMsg("aps len", len(aps), ShouldEqual, 2)
			SoMsg("path #1", getPathStrings(aps), ShouldContain,
				"[1-ff00:0:133#1019 1-ff00:0:132#1910 "+
					"1-ff00:0:132#1916 1-ff00:0:131#1619]")
			SoMsg("path #2", getPathStrings(aps), ShouldContain,
				"[1-ff00:0:133#101902 1-ff00:0:132#191002 "+
					"1-ff00:0:132#1916 1-ff00:0:131#1619]")
		})
	})
}

var allowEntry = &pathpol.ACLEntry{Action: pathpol.Allow, Rule: &sciond.PathInterface{}}
var denyEntry = &pathpol.ACLEntry{Action: pathpol.Deny, Rule: &sciond.PathInterface{}}

func TestQueryFilter(t *testing.T) {
	g := graph.NewDefaultGraph()
	pm := NewPR(t, g, 0, 0, 0)
	srcIA := xtest.MustParseIA("1-ff00:0:133")
	dstIA := xtest.MustParseIA("1-ff00:0:131")
	Convey("Query with policy filter, only one path should remain, default deny", t, func() {
		pp, err := sciond.NewPathInterface("0-0#0")
		xtest.FailOnErr(t, err)
		policy := &pathpol.Policy{ACL: &pathpol.ACL{Entries: []*pathpol.ACLEntry{
			{Action: pathpol.Allow, Rule: &pp},
			denyEntry,
		}}}
		aps := pm.QueryFilter(srcIA, dstIA, policy)
		SoMsg("aps len", len(aps), ShouldEqual, 1)
		SoMsg("path", getPathStrings(aps), ShouldContain,
			"[1-ff00:0:133#1019 1-ff00:0:132#1910 "+
				"1-ff00:0:132#1916 1-ff00:0:131#1619]")
	})

	Convey("Query with policy filter, only one path should remain, default allow", t, func() {
		pp, err := sciond.NewPathInterface("1-ff00:0:134#1910")
		xtest.FailOnErr(t, err)
		policy := &pathpol.Policy{ACL: &pathpol.ACL{Entries: []*pathpol.ACLEntry{
			{Action: pathpol.Allow, Rule: &pp},
			allowEntry,
		}}}
		aps := pm.QueryFilter(srcIA, dstIA, policy)
		SoMsg("aps len", len(aps), ShouldEqual, 1)
		SoMsg("path", getPathStrings(aps), ShouldContain,
			"[1-ff00:0:133#1019 1-ff00:0:132#1910 "+
				"1-ff00:0:132#1916 1-ff00:0:131#1619]")
	})

	Convey("Query with policy filter, no path should remain", t, func() {
		pp, err := sciond.NewPathInterface("1-ff00:0:132#1910")
		xtest.FailOnErr(t, err)
		policy := &pathpol.Policy{ACL: &pathpol.ACL{Entries: []*pathpol.ACLEntry{
			{Action: pathpol.Deny, Rule: &pp},
			denyEntry,
		}}}
		aps := pm.QueryFilter(srcIA, dstIA, policy)
		SoMsg("aps len", len(aps), ShouldEqual, 0)
	})
}

func TestACLPolicyFilter(t *testing.T) {
	Convey("Query with ACL policy filter", t, func() {
		g := graph.NewDefaultGraph()
		pm := NewPR(t, g, 0, 0, 0)
		srcIA := xtest.MustParseIA("2-ff00:0:222")
		dstIA := xtest.MustParseIA("1-ff00:0:131")
		pp, _ := sciond.NewPathInterface("1-ff00:0:121#0")
		policy := &pathpol.Policy{ACL: &pathpol.ACL{Entries: []*pathpol.ACLEntry{
			{
				Action: pathpol.Deny,
				Rule:   &pp,
			},
			allowEntry,
		}}}
		aps := pm.QueryFilter(srcIA, dstIA, policy)
		SoMsg("aps len", len(aps), ShouldEqual, 2)
	})

	Convey("Query with longer ACL policy filter", t, func() {
		g := graph.NewDefaultGraph()
		pm := NewPR(t, g, 0, 0, 0)
		srcIA := xtest.MustParseIA("2-ff00:0:222")
		dstIA := xtest.MustParseIA("1-ff00:0:131")
		pp, _ := sciond.NewPathInterface("1-ff00:0:121#0")
		pp2, _ := sciond.NewPathInterface("2-ff00:0:211#2327")
		policy := &pathpol.Policy{ACL: &pathpol.ACL{Entries: []*pathpol.ACLEntry{
			{
				Action: pathpol.Deny,
				Rule:   &pp,
			},
			{Action: pathpol.Deny, Rule: &pp2},
			allowEntry,
		}}}
		aps := pm.QueryFilter(srcIA, dstIA, policy)
		SoMsg("aps len", len(aps), ShouldEqual, 1)
	})
}

func TestRegister(t *testing.T) {
	Convey("Register for path, receive 0 responses", t, func() {
		g := graph.NewDefaultGraph()
		// Remove link between 1-ff00:0:132 and 1-ff00:0:131 and the peering from 1-ff00:0:133 to
		// 1-ff00:0:122 so that the initial path set is nil
		g.RemoveLink(graph.If_133_X_132_X)
		g.RemoveLink(graph.If_133_X_122_X)
		pm := NewPR(t, g, 100, 100, 100)
		srcIA := xtest.MustParseIA("1-ff00:0:133")
		dstIA := xtest.MustParseIA("1-ff00:0:131")

		sp, err := pm.Watch(srcIA, dstIA)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("aps", len(sp.Load().APS), ShouldEqual, 0)

		Convey("Wait 200ms, the APS should contain fresh paths", func() {
			// Re-add the link between 1-ff00:0:132 and 1-ff00:0:131; the path manager will
			// update APS behind the scenes (after a normal refire of one
			// second), so it should contain the path after 4 seconds.
			g.AddLink("1-ff00:0:133", graph.If_133_X_132_X,
				"1-ff00:0:132", graph.If_132_X_133_X, false)
			<-time.After(200 * time.Millisecond)
			SoMsg("aps", len(sp.Load().APS), ShouldEqual, 1)
			SoMsg("path", getPathStrings(sp.Load().APS), ShouldContain,
				"[1-ff00:0:133#1019 1-ff00:0:132#1910 "+
					"1-ff00:0:132#1916 1-ff00:0:131#1619]")
		})
	})
}

func TestRegisterFilter(t *testing.T) {
	Convey("Register filter 1-ff00:0:132#1910", t, func() {
		g := graph.NewDefaultGraph()
		pm := NewPR(t, g, 500, 500, 1000)
		srcIA := xtest.MustParseIA("1-ff00:0:133")
		dstIA := xtest.MustParseIA("1-ff00:0:131")

		pp, err := spathmeta.NewPathPredicate("1-ff00:0:132#1910")
		xtest.FailOnErr(t, err)

		filter := pktcls.NewActionFilterPaths("test-1-ff00:0:131#1619",
			pktcls.NewCondPathPredicate(pp))

		sp, err := pm.WatchFilter(srcIA, dstIA, filter)
		SoMsg("len aps", len(sp.Load().APS), ShouldEqual, 1)
		SoMsg("path", getPathStrings(sp.Load().APS), ShouldContain,
			"[1-ff00:0:133#1019 1-ff00:0:132#1910 "+
				"1-ff00:0:132#1916 1-ff00:0:131#1619]")
	})
}

func TestRevoke(t *testing.T) {
	Convey("Populate cache via Query, Watch, WatchFilter for different destinations", t, func() {
		g := graph.NewDefaultGraph()
		// Remove peering 133 -> 122 to have a simple up path 133 -> 131
		g.RemoveLink(graph.If_133_X_122_X)
		pm := NewPR(t, g, 60, 60, 60)
		// Query: 1-ff00:0:133 -> 1-ff00:0:131
		querySrc := xtest.MustParseIA("1-ff00:0:133")
		queryDst := xtest.MustParseIA("1-ff00:0:131")
		// Watch/WatchFilter: 1-ff00:0:122 -> 2-ff00:0:220
		watchSrc := xtest.MustParseIA("1-ff00:0:122")
		watchDst := xtest.MustParseIA("2-ff00:0:220")

		aps := pm.Query(querySrc, queryDst)
		apsCheckPaths("path", aps,
			"[1-ff00:0:133#1019 1-ff00:0:132#1910 1-ff00:0:132#1916 1-ff00:0:131#1619]")

		sp, err := pm.Watch(watchSrc, watchDst)
		SoMsg("watch: ee", err, ShouldBeNil)
		apsCheckPaths("watch", sp.Load().APS,
			"[1-ff00:0:122#1815 1-ff00:0:121#1518 1-ff00:0:121#1530 "+
				"1-ff00:0:120#3015 1-ff00:0:120#3022 2-ff00:0:220#2230]",
			"[1-ff00:0:122#1815 1-ff00:0:121#1518 1-ff00:0:121#1530 "+
				"1-ff00:0:120#3015 1-ff00:0:120#3122 2-ff00:0:220#2231]")

		pp, err := spathmeta.NewPathPredicate("1-ff00:0:121#1518")
		xtest.FailOnErr(t, err)
		filter := pktcls.NewActionFilterPaths("test-1-ff00:0:121#1518",
			pktcls.NewCondPathPredicate(pp))
		spf, err := pm.WatchFilter(watchSrc, watchDst, filter)
		SoMsg("watch filter: err", err, ShouldBeNil)
		apsCheckPaths("watch filter", spf.Load().APS,
			"[1-ff00:0:122#1815 1-ff00:0:121#1518 1-ff00:0:121#1530 "+
				"1-ff00:0:120#3015 1-ff00:0:120#3022 2-ff00:0:220#2230]",
			"[1-ff00:0:122#1815 1-ff00:0:121#1518 1-ff00:0:121#1530 "+
				"1-ff00:0:120#3015 1-ff00:0:120#3122 2-ff00:0:220#2231]")

		Convey("Revoke a path that's not part of any path set", func() {
			g.RemoveLink(graph.If_130_A_110_X)
			pm.cache.revoke(uifidFromValues(xtest.MustParseIA("1-ff00:0:130"),
				graph.If_130_A_110_X))
			aps := pm.Query(querySrc, queryDst)
			apsCheckPaths("path", aps,
				"[1-ff00:0:133#1019 1-ff00:0:132#1910 1-ff00:0:132#1916 1-ff00:0:131#1619]")
			apsCheckPaths("watch", sp.Load().APS,
				"[1-ff00:0:122#1815 1-ff00:0:121#1518 1-ff00:0:121#1530 "+
					"1-ff00:0:120#3015 1-ff00:0:120#3022 2-ff00:0:220#2230]",
				"[1-ff00:0:122#1815 1-ff00:0:121#1518 1-ff00:0:121#1530 "+
					"1-ff00:0:120#3015 1-ff00:0:120#3122 2-ff00:0:220#2231]")
			apsCheckPaths("watch filter", spf.Load().APS,
				"[1-ff00:0:122#1815 1-ff00:0:121#1518 1-ff00:0:121#1530 "+
					"1-ff00:0:120#3015 1-ff00:0:120#3022 2-ff00:0:220#2230]",
				"[1-ff00:0:122#1815 1-ff00:0:121#1518 1-ff00:0:121#1530 "+
					"1-ff00:0:120#3015 1-ff00:0:120#3122 2-ff00:0:220#2231]")
		})
		Convey("Revoke a path that's in Query, but not in Watch/WatchFilter path sets", func() {
			// Disconnect #1019
			// Note that the revoke below only invalidates the cache and
			// does not inform sciond. This means that the path manager
			// reaches 0 paths after the revocation, thus forcing a requery
			// to sciond behind the scenes, which gets back the same path.
			g.RemoveLink(graph.If_133_X_132_X)
			pm.cache.revoke(uifidFromValues(xtest.MustParseIA("1-ff00:0:133"),
				graph.If_133_X_132_X))
			aps := pm.Query(querySrc, queryDst)
			apsCheckPaths("path", aps)
			apsCheckPaths("watch", sp.Load().APS,
				"[1-ff00:0:122#1815 1-ff00:0:121#1518 1-ff00:0:121#1530 "+
					"1-ff00:0:120#3015 1-ff00:0:120#3022 2-ff00:0:220#2230]",
				"[1-ff00:0:122#1815 1-ff00:0:121#1518 1-ff00:0:121#1530 "+
					"1-ff00:0:120#3015 1-ff00:0:120#3122 2-ff00:0:220#2231]")
			apsCheckPaths("watch filter", spf.Load().APS,
				"[1-ff00:0:122#1815 1-ff00:0:121#1518 1-ff00:0:121#1530 "+
					"1-ff00:0:120#3015 1-ff00:0:120#3022 2-ff00:0:220#2230]",
				"[1-ff00:0:122#1815 1-ff00:0:121#1518 1-ff00:0:121#1530 "+
					"1-ff00:0:120#3015 1-ff00:0:120#3122 2-ff00:0:220#2231]")
		})
		Convey("Revoke a path that's in Watch and WatchFilter, but not in Query", func() {
			// Disconnect #1815
			// The revoke below only invalidates the cache. Because watches
			// do not requery sciond automatically (like the previous
			// test), they will be left with 0 paths.
			g.RemoveLink(graph.If_122_X_121_X)
			pm.cache.revoke(uifidFromValues(watchSrc, graph.If_122_X_121_X))
			apsCheckPaths("path", aps,
				"[1-ff00:0:133#1019 1-ff00:0:132#1910 1-ff00:0:132#1916 1-ff00:0:131#1619]")
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

func getPathStrings(aps spathmeta.AppPathSet) []string {
	var ss []string
	for _, v := range aps {
		ss = append(ss, fmt.Sprintf("%v", v.Entry.Path.Interfaces))
	}
	return ss
}

func apsCheckPaths(desc string, aps spathmeta.AppPathSet, expValues ...string) {
	SoMsg(fmt.Sprintf("%s: len", desc), len(aps), ShouldEqual, len(expValues))
	for i, value := range expValues {
		SoMsg(fmt.Sprintf("%s: path %d", desc, i), getPathStrings(aps), ShouldContain, value)
	}
}
