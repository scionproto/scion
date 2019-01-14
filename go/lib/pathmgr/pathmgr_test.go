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
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/sciond/mock_sciond"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

const timeUnitDuration time.Duration = 10 * time.Millisecond

func getDuration(units time.Duration) time.Duration {
	return units * timeUnitDuration
}

func TestQuery(t *testing.T) {
	Convey("Query, we have 0 paths and SCIOND is asked again, receive 1 path", t, func() {
		g := graph.NewDefaultGraph()
		pm := NewPR(t, g, 0, 0)
		srcIA := xtest.MustParseIA("1-ff00:0:133")
		dstIA := xtest.MustParseIA("1-ff00:0:131")

		aps := pm.Query(context.Background(), srcIA, dstIA, sciond.PathReqFlags{})
		SoMsg("aps len", len(aps), ShouldEqual, 1)
		Convey("Query immediately, get paths", func() {
			aps := pm.Query(context.Background(), srcIA, dstIA, sciond.PathReqFlags{})
			SoMsg("aps len", len(aps), ShouldEqual, 1)
			SoMsg("path", getPathStrings(aps), ShouldContain,
				"[1-ff00:0:133#1019 1-ff00:0:132#1910 "+
					"1-ff00:0:132#1916 1-ff00:0:131#1619]")
		})
		Convey("Then query again and get new paths", func() {
			// Add new path between 1-ff00:0:133 and 1-ff00:0:131
			g.AddLink("1-ff00:0:133", 101902, "1-ff00:0:132", 191002, false)
			aps := pm.Query(context.Background(), srcIA, dstIA, sciond.PathReqFlags{})
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

var allowEntry = &pathpol.ACLEntry{Action: pathpol.Allow, Rule: pathpol.NewHopPredicate()}
var denyEntry = &pathpol.ACLEntry{Action: pathpol.Deny, Rule: pathpol.NewHopPredicate()}

func TestQueryFilter(t *testing.T) {
	g := graph.NewDefaultGraph()
	pm := NewPR(t, g, 0, 0)
	srcIA := xtest.MustParseIA("1-ff00:0:133")
	dstIA := xtest.MustParseIA("1-ff00:0:131")
	Convey("Query with policy filter, only one path should remain, default deny", t, func() {
		pp, err := pathpol.HopPredicateFromString("0-0#0")
		xtest.FailOnErr(t, err)
		policy := &pathpol.Policy{ACL: &pathpol.ACL{Entries: []*pathpol.ACLEntry{
			{Action: pathpol.Allow, Rule: pp},
			denyEntry,
		}}}
		aps := pm.QueryFilter(context.Background(), srcIA, dstIA, policy)
		SoMsg("aps len", len(aps), ShouldEqual, 1)
		SoMsg("path", getPathStrings(aps), ShouldContain,
			"[1-ff00:0:133#1019 1-ff00:0:132#1910 "+
				"1-ff00:0:132#1916 1-ff00:0:131#1619]")
	})
	Convey("Query with policy filter, only one path should remain, default allow", t, func() {
		pp, err := pathpol.HopPredicateFromString("1-ff00:0:134#1910")
		xtest.FailOnErr(t, err)
		policy := &pathpol.Policy{ACL: &pathpol.ACL{Entries: []*pathpol.ACLEntry{
			{Action: pathpol.Allow, Rule: pp},
			allowEntry,
		}}}
		aps := pm.QueryFilter(context.Background(), srcIA, dstIA, policy)
		SoMsg("aps len", len(aps), ShouldEqual, 1)
		SoMsg("path", getPathStrings(aps), ShouldContain,
			"[1-ff00:0:133#1019 1-ff00:0:132#1910 "+
				"1-ff00:0:132#1916 1-ff00:0:131#1619]")
	})
	Convey("Query with policy filter, no path should remain", t, func() {
		pp, err := pathpol.HopPredicateFromString("1-ff00:0:132#1910")
		xtest.FailOnErr(t, err)
		policy := &pathpol.Policy{ACL: &pathpol.ACL{Entries: []*pathpol.ACLEntry{
			{Action: pathpol.Deny, Rule: pp},
			denyEntry,
		}}}
		aps := pm.QueryFilter(context.Background(), srcIA, dstIA, policy)
		SoMsg("aps len", len(aps), ShouldEqual, 0)
	})
}

func TestACLPolicyFilter(t *testing.T) {
	Convey("Query with ACL policy filter", t, func() {
		g := graph.NewDefaultGraph()
		pm := NewPR(t, g, 0, 0)
		srcIA := xtest.MustParseIA("2-ff00:0:222")
		dstIA := xtest.MustParseIA("1-ff00:0:131")
		pp, _ := pathpol.HopPredicateFromString("1-ff00:0:121#0")
		policy := &pathpol.Policy{ACL: &pathpol.ACL{Entries: []*pathpol.ACLEntry{
			{
				Action: pathpol.Deny,
				Rule:   pp,
			},
			allowEntry,
		}}}
		aps := pm.QueryFilter(context.Background(), srcIA, dstIA, policy)
		SoMsg("aps len", len(aps), ShouldEqual, 2)
	})
	Convey("Query with longer ACL policy filter", t, func() {
		g := graph.NewDefaultGraph()
		pm := NewPR(t, g, 0, 0)
		srcIA := xtest.MustParseIA("2-ff00:0:222")
		dstIA := xtest.MustParseIA("1-ff00:0:131")
		pp, _ := pathpol.HopPredicateFromString("1-ff00:0:121#0")
		pp2, _ := pathpol.HopPredicateFromString("2-ff00:0:211#2327")
		policy := &pathpol.Policy{ACL: &pathpol.ACL{Entries: []*pathpol.ACLEntry{
			{
				Action: pathpol.Deny,
				Rule:   pp,
			},
			{Action: pathpol.Deny, Rule: pp2},
			allowEntry,
		}}}
		aps := pm.QueryFilter(context.Background(), srcIA, dstIA, policy)
		SoMsg("aps len", len(aps), ShouldEqual, 1)
	})
}

func TestWatchCount(t *testing.T) {
	src := xtest.MustParseIA("1-ff00:0:111")
	dst := xtest.MustParseIA("1-ff00:0:110")
	Convey("Given a path manager", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		sd := mock_sciond.NewMockConnector(ctrl)
		pr := New(sd, Timers{}, nil)
		Convey("the count is initially 0", func() {
			So(pr.WatchCount(), ShouldEqual, 0)
		})
		Convey("and adding a watch", func() {
			sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
				buildSDAnswer(), nil,
			).AnyTimes()
			sp, err := pr.Watch(context.Background(), src, dst)
			xtest.FailOnErr(t, err)
			Convey("the number of watches increases to 1", func() {
				So(pr.WatchCount(), ShouldEqual, 1)
			})
			Convey("if the watch is destroyed", func() {
				sp.Destroy()
				Convey("the number of watches decreases to 0", func() {
					So(pr.WatchCount(), ShouldEqual, 0)
				})
			})
		})
	})
}

func TestWatchPolling(t *testing.T) {
	src := xtest.MustParseIA("1-ff00:0:111")
	dst := xtest.MustParseIA("1-ff00:0:110")
	Convey("Given a path manager", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		sd := mock_sciond.NewMockConnector(ctrl)
		gomock.InOrder(
			sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
				buildSDAnswer(), nil,
			),
			sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
				buildSDAnswer(
					"1-ff00:0:111#105 1-ff00:0:130#1002 1-ff00:0:130#1004 1-ff00:0:110#2",
				), nil,
			).MinTimes(1),
		)
		pr := New(sd, Timers{ErrorRefire: getDuration(1)}, nil)
		Convey("and adding a watch that retrieves zero paths", func() {
			sp, err := pr.Watch(context.Background(), src, dst)
			xtest.FailOnErr(t, err)
			Convey("there are 0 paths currently available", func() {
				So(len(sp.Load().APS), ShouldEqual, 0)
				Convey("and after waiting, we get new paths.", func() {
					time.Sleep(getDuration(4))
					So(len(sp.Load().APS), ShouldEqual, 1)
				})
			})
		})
	})
}

func TestWatchFilter(t *testing.T) {
	src := xtest.MustParseIA("1-ff00:0:111")
	dst := xtest.MustParseIA("1-ff00:0:110")
	Convey("Given a path manager", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		sd := mock_sciond.NewMockConnector(ctrl)
		gomock.InOrder(
			sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
				buildSDAnswer(
					"1-ff00:0:111#104 1-ff00:0:120#5 1-ff00:0:120#6 1-ff00:0:110#1",
				), nil,
			),
			sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
				buildSDAnswer(
					"1-ff00:0:111#105 1-ff00:0:130#1002 1-ff00:0:130#1004 1-ff00:0:110#2",
					"1-ff00:0:111#104 1-ff00:0:120#5 1-ff00:0:120#6 1-ff00:0:110#1",
				), nil,
			).AnyTimes(),
		)
		pr := New(sd, Timers{ErrorRefire: getDuration(1)}, nil)
		Convey("and adding a watch that should retrieve 1 path", func() {
			seq, err := pathpol.NewSequence("1-ff00:0:111#105 0 0")
			xtest.FailOnErr(t, err)
			filter := pathpol.NewPolicy("test-1-ff00:0:111#105", nil, seq, nil)

			sp, err := pr.WatchFilter(context.Background(), src, dst, filter)
			xtest.FailOnErr(t, err)
			Convey("there are 0 paths due to filtering", func() {
				So(len(sp.Load().APS), ShouldEqual, 0)
				Convey("and after waiting, we get 1 path that is not filtered.", func() {
					time.Sleep(getDuration(4))
					So(len(sp.Load().APS), ShouldEqual, 1)
				})
			})
		})
	})
}

func TestRevoke(t *testing.T) {
	src := xtest.MustParseIA("1-ff00:0:111")
	dst := xtest.MustParseIA("1-ff00:0:110")
	Convey("Given a path manager", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		sd := mock_sciond.NewMockConnector(ctrl)
		pr := New(sd, Timers{}, nil)
		Convey("and a watch that retrieves one path", func() {
			sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
				buildSDAnswer(
					"1-ff00:0:111#105 1-ff00:0:130#1002 1-ff00:0:130#1004 1-ff00:0:110#2",
				), nil,
			)
			sp, err := pr.Watch(context.Background(), src, dst)
			xtest.FailOnErr(t, err)
			Convey("revoking an IFID that matches the path", func() {
				sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
					&sciond.RevReply{Result: sciond.RevValid}, nil,
				)
				pr.Revoke(context.Background(), newTestRev(t, "1-ff00:0:130#1002"))
				Convey("deletes the path", func() {
					So(len(sp.Load().APS), ShouldEqual, 0)
				})
			})
			Convey("revoking an IFID that does not match the path", func() {
				sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
					&sciond.RevReply{Result: sciond.RevValid}, nil,
				)
				pr.Revoke(context.Background(), newTestRev(t, "2-ff00:0:1#1"))
				Convey("does not delete the path", func() {
					So(len(sp.Load().APS), ShouldEqual, 1)
				})
			})
			Convey("trying to revoke an IFID, but SCIOND encounters an error", func() {
				sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
					nil, fmt.Errorf("some error"),
				)
				pr.Revoke(context.Background(), newTestRev(t, "1-ff00:0:130#1002"))
				Convey("does not delete the path", func() {
					So(len(sp.Load().APS), ShouldEqual, 1)
				})
			})
			Convey("trying to revoke an IFID, but the revocation is invalid", func() {
				sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
					&sciond.RevReply{Result: sciond.RevInvalid}, nil,
				)
				pr.Revoke(context.Background(), newTestRev(t, "1-ff00:0:130#1002"))
				Convey("does not delete the path", func() {
					So(len(sp.Load().APS), ShouldEqual, 1)
				})
			})
			Convey("trying to revoke an IFID, but the revocation is stale", func() {
				sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
					&sciond.RevReply{Result: sciond.RevStale}, nil,
				)
				pr.Revoke(context.Background(), newTestRev(t, "1-ff00:0:130#1002"))
				Convey("does not delete the path", func() {
					So(len(sp.Load().APS), ShouldEqual, 1)
				})
			})
			Convey("trying to revoke an IFID, but the revocation is unknown", func() {
				sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
					&sciond.RevReply{Result: sciond.RevUnknown}, nil,
				)
				pr.Revoke(context.Background(), newTestRev(t, "1-ff00:0:130#1002"))
				Convey("deletes the path", func() {
					So(len(sp.Load().APS), ShouldEqual, 0)
				})
			})
		})
		Convey("and a watch that retrieves two paths", func() {
			sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
				buildSDAnswer(
					"1-ff00:0:111#105 1-ff00:0:130#1002 1-ff00:0:130#1004 1-ff00:0:110#2",
					"1-ff00:0:111#104 1-ff00:0:120#5 1-ff00:0:120#6 1-ff00:0:110#1",
				), nil,
			)
			sp, err := pr.Watch(context.Background(), src, dst)
			xtest.FailOnErr(t, err)
			Convey("revoking an IFID that matches one path", func() {
				sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
					&sciond.RevReply{Result: sciond.RevValid}, nil,
				)
				pr.Revoke(context.Background(), newTestRev(t, "1-ff00:0:130#1002"))
				Convey("leaves one path remaining", func() {
					So(len(sp.Load().APS), ShouldEqual, 1)
				})
			})
		})
	})
}

func newTestRev(t *testing.T, rev string) *path_mgmt.SignedRevInfo {
	pi := mustParsePI(rev)
	signedRevInfo, err := path_mgmt.NewSignedRevInfo(
		&path_mgmt.RevInfo{
			IfID:     pi.IfID,
			RawIsdas: pi.RawIsdas,
		}, nil)
	xtest.FailOnErr(t, err)
	return signedRevInfo
}

func NewPR(t *testing.T, g *graph.Graph, normalRefire, errorRefire time.Duration) Resolver {

	t.Helper()

	mockConn, err := sciond.NewMockService(g).Connect()
	xtest.FailOnErr(t, err)

	return New(
		mockConn,
		Timers{
			NormalRefire: normalRefire,
			ErrorRefire:  errorRefire,
		},
		log.Root(),
	)
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
