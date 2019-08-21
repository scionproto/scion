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
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/sciond/mock_sciond"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/lib/xtest"
)

const timeUnitDuration time.Duration = 10 * time.Millisecond

func getDuration(units time.Duration) time.Duration {
	return units * timeUnitDuration
}

func TestQuery(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sd := mock_sciond.NewMockConnector(ctrl)
	pm := New(sd, Timers{})

	srcIA := xtest.MustParseIA("1-ff00:0:133")
	dstIA := xtest.MustParseIA("1-ff00:0:131")

	t.Run("Query immediately, get paths", func(t *testing.T) {
		paths := []string{
			"1-ff00:0:133#1019 1-ff00:0:132#1910 " + "1-ff00:0:132#1916 1-ff00:0:131#1619",
		}

		sd.EXPECT().Paths(gomock.Any(), dstIA, srcIA, gomock.Any(), gomock.Any()).Return(
			buildSDAnswer(paths...), nil,
		)

		aps := pm.Query(context.Background(), srcIA, dstIA, sciond.PathReqFlags{})
		assert.Len(t, aps, 1)
		assert.Contains(t, getPathStrings(aps),
			"[1-ff00:0:133#1019 1-ff00:0:132#1910 "+"1-ff00:0:132#1916 1-ff00:0:131#1619]")
	})

	t.Run("Then query again and get new paths", func(t *testing.T) {
		paths := []string{
			"1-ff00:0:133#1019 1-ff00:0:132#1910 " + "1-ff00:0:132#1916 1-ff00:0:131#1619",
			"1-ff00:0:133#101902 1-ff00:0:132#191002 " + "1-ff00:0:132#1916 1-ff00:0:131#1619",
		}

		sd.EXPECT().Paths(gomock.Any(), dstIA, srcIA, gomock.Any(), gomock.Any()).Return(
			buildSDAnswer(paths...), nil,
		)

		aps := pm.Query(context.Background(), srcIA, dstIA, sciond.PathReqFlags{})
		assert.Len(t, aps, 2)
		assert.Contains(t, getPathStrings(aps),
			"[1-ff00:0:133#1019 1-ff00:0:132#1910 "+"1-ff00:0:132#1916 1-ff00:0:131#1619]")

		assert.Contains(t, getPathStrings(aps),
			"[1-ff00:0:133#101902 1-ff00:0:132#191002 "+"1-ff00:0:132#1916 1-ff00:0:131#1619]")
	})
}

var allowEntry = &pathpol.ACLEntry{Action: pathpol.Allow, Rule: pathpol.NewHopPredicate()}
var denyEntry = &pathpol.ACLEntry{Action: pathpol.Deny, Rule: pathpol.NewHopPredicate()}

func TestQueryFilter(t *testing.T) {
	t.Log("Query with policy filter")
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sd := mock_sciond.NewMockConnector(ctrl)
	pm := New(sd, Timers{})

	srcIA := xtest.MustParseIA("1-ff00:0:133")
	dstIA := xtest.MustParseIA("1-ff00:0:131")

	paths := []string{
		"1-ff00:0:133#1019 1-ff00:0:132#1910 " + "1-ff00:0:132#1916 1-ff00:0:131#1619",
	}

	sd.EXPECT().Paths(gomock.Any(), dstIA, srcIA, gomock.Any(), gomock.Any()).Return(
		buildSDAnswer(paths...), nil,
	).AnyTimes()

	t.Run("Hop does not exist in paths, default deny", func(t *testing.T) {
		pp, err := pathpol.HopPredicateFromString("0-0#0")
		xtest.FailOnErr(t, err)
		policy := &pathpol.Policy{ACL: &pathpol.ACL{Entries: []*pathpol.ACLEntry{
			{Action: pathpol.Allow, Rule: pp},
			denyEntry,
		}}}

		aps := pm.QueryFilter(context.Background(), srcIA, dstIA, policy)
		assert.Len(t, aps, 1, "only one path should remain")
		assert.Contains(t, getPathStrings(aps),
			"[1-ff00:0:133#1019 1-ff00:0:132#1910 "+
				"1-ff00:0:132#1916 1-ff00:0:131#1619]")
	})

	t.Run("Hop does not exist paths, default allow", func(t *testing.T) {
		pp, err := pathpol.HopPredicateFromString("1-ff00:0:134#1910")
		xtest.FailOnErr(t, err)
		policy := &pathpol.Policy{ACL: &pathpol.ACL{Entries: []*pathpol.ACLEntry{
			{Action: pathpol.Allow, Rule: pp},
			allowEntry,
		}}}
		aps := pm.QueryFilter(context.Background(), srcIA, dstIA, policy)
		assert.Len(t, aps, 1, "only one path should remain")
		assert.Contains(t, getPathStrings(aps),
			"[1-ff00:0:133#1019 1-ff00:0:132#1910 "+
				"1-ff00:0:132#1916 1-ff00:0:131#1619]")
	})

	t.Run("Hop exists in paths, default deny ", func(t *testing.T) {
		pp, err := pathpol.HopPredicateFromString("1-ff00:0:132#1910")
		xtest.FailOnErr(t, err)
		policy := &pathpol.Policy{ACL: &pathpol.ACL{Entries: []*pathpol.ACLEntry{
			{Action: pathpol.Deny, Rule: pp},
			denyEntry,
		}}}
		aps := pm.QueryFilter(context.Background(), srcIA, dstIA, policy)
		assert.Len(t, aps, 0, "no path should remain")
	})
}

func TestACLPolicyFilter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sd := mock_sciond.NewMockConnector(ctrl)
	pm := New(sd, Timers{})

	srcIA := xtest.MustParseIA("2-ff00:0:222")
	dstIA := xtest.MustParseIA("1-ff00:0:131")

	paths := []string{
		fmt.Sprintf("%s#1019 1-ff00:0:122#1910 1-ff00:0:122#1916 %s#1619",
			srcIA.String(), dstIA.String()),
		fmt.Sprintf("%s#1019 2-ff00:0:211#1911 2-ff00:0:211#2327 %s#1619",
			srcIA.String(), dstIA.String()),
		fmt.Sprintf("%s#1019 1-ff00:0:121#1912 1-ff00:0:121#2328 %s#1619",
			srcIA.String(), dstIA.String()),
	}

	sd.EXPECT().Paths(gomock.Any(), dstIA, srcIA, gomock.Any(), gomock.Any()).Return(
		buildSDAnswer(paths...), nil,
	).AnyTimes()

	pp, _ := pathpol.HopPredicateFromString("1-ff00:0:121#0")
	t.Run("Query with ACL policy filter", func(t *testing.T) {
		policy := &pathpol.Policy{ACL: &pathpol.ACL{Entries: []*pathpol.ACLEntry{
			{Action: pathpol.Deny, Rule: pp},
			allowEntry,
		}}}
		aps := pm.QueryFilter(context.Background(), srcIA, dstIA, policy)
		assert.Len(t, aps, 2)
	})

	t.Run("Query with longer ACL policy filter", func(t *testing.T) {
		pp2, _ := pathpol.HopPredicateFromString("2-ff00:0:211#2327")
		policy := &pathpol.Policy{ACL: &pathpol.ACL{Entries: []*pathpol.ACLEntry{
			{Action: pathpol.Deny, Rule: pp},
			{Action: pathpol.Deny, Rule: pp2},
			allowEntry,
		}}}
		aps := pm.QueryFilter(context.Background(), srcIA, dstIA, policy)
		assert.Len(t, aps, 1)
	})
}

func TestWatchCount(t *testing.T) {
	t.Log("Given a path manager and adding a watch")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sd := mock_sciond.NewMockConnector(ctrl)
	pr := New(sd, Timers{})

	src := xtest.MustParseIA("1-ff00:0:111")
	dst := xtest.MustParseIA("1-ff00:0:110")

	sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
		buildSDAnswer(), nil,
	).AnyTimes()

	assert.Equal(t, pr.WatchCount(), 0, " the count is initially 0")
	sp, err := pr.Watch(context.Background(), src, dst)
	xtest.FailOnErr(t, err)
	assert.Equal(t, pr.WatchCount(), 1, "the number of watches increases to 1")
	sp.Destroy()
	assert.Equal(t, pr.WatchCount(), 0, "the number of watches decreases to 0")
}

func TestWatchPolling(t *testing.T) {
	t.Log("Given a path manager and adding a watch that retrieves zero paths")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sd := mock_sciond.NewMockConnector(ctrl)
	pr := New(sd, Timers{ErrorRefire: getDuration(1)})

	src := xtest.MustParseIA("1-ff00:0:111")
	dst := xtest.MustParseIA("1-ff00:0:110")
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

	sp, err := pr.Watch(context.Background(), src, dst)
	xtest.FailOnErr(t, err)
	assert.Len(t, sp.Load().APS, 0, "there are 0 paths currently available")
	time.Sleep(getDuration(4))
	assert.Len(t, sp.Load().APS, 1, "and after waiting, we get new paths")
}

func TestWatchFilter(t *testing.T) {
	t.Log("Given a path manager and adding a watch that should retrieve 1 path")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	sd := mock_sciond.NewMockConnector(ctrl)
	pr := New(sd, Timers{ErrorRefire: getDuration(1)})

	src := xtest.MustParseIA("1-ff00:0:111")
	dst := xtest.MustParseIA("1-ff00:0:110")
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

	seq, err := pathpol.NewSequence("1-ff00:0:111#105 0 0")
	xtest.FailOnErr(t, err)
	filter := pathpol.NewPolicy("test-1-ff00:0:111#105", nil, seq, nil)

	sp, err := pr.WatchFilter(context.Background(), src, dst, filter)
	xtest.FailOnErr(t, err)
	assert.Len(t, sp.Load().APS, 0, "there are 0 paths due to filtering")
	time.Sleep(getDuration(4))
	assert.Len(t, sp.Load().APS, 1, "and after waiting, we get 1 path that is not filtered")
}

func TestRevokeFastRecovery(t *testing.T) {
	t.Log("Given a path manager with a long normal timer and very small error timer")
	t.Log("A revocation that deletes everything triggers an immediate requery")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	src := xtest.MustParseIA("1-ff00:0:111")
	dst := xtest.MustParseIA("1-ff00:0:110")

	sd := mock_sciond.NewMockConnector(ctrl)
	pr := New(sd, Timers{NormalRefire: getDuration(100), ErrorRefire: getDuration(1)})

	sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
		buildSDAnswer(
			"1-ff00:0:111#105 1-ff00:0:130#1002 1-ff00:0:130#1004 1-ff00:0:110#2",
		), nil,
	)

	_, err := pr.Watch(context.Background(), src, dst)
	xtest.FailOnErr(t, err)

	// Once everything is revoked a fast request is immediately
	// triggered. We check for at least 2 iterations to make sure we
	// are in error recovery mode, and the aggressive timer is used.
	// We actually test that the mock .{Revnotifications,Paths} functions are
	// being called within a 5 sec time period. It will fail with "missing
	// call(s)" error message
	gomock.InOrder(
		sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
			&sciond.RevReply{Result: sciond.RevValid}, nil,
		),
		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(),
			gomock.Any()).Return(
			buildSDAnswer(), nil,
		).MinTimes(2),
	)
	pr.Revoke(context.Background(), newTestRev(t, "1-ff00:0:130#1002"))
	time.Sleep(getDuration(5))
}

func TestRevoke(t *testing.T) {
	t.Log("Given a path manager and a watch that")

	src := xtest.MustParseIA("1-ff00:0:111")
	dst := xtest.MustParseIA("1-ff00:0:110")
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("retrieves one path revoking an IFID that matches the path", func(t *testing.T) {
		sd := mock_sciond.NewMockConnector(ctrl)
		pr := New(sd, Timers{})

		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
			buildSDAnswer(
				"1-ff00:0:111#105 1-ff00:0:130#1002 1-ff00:0:130#1004 1-ff00:0:110#2",
			), nil,
		)
		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
			buildSDAnswer(), nil,
		).AnyTimes()
		sp, err := pr.Watch(context.Background(), src, dst)
		xtest.FailOnErr(t, err)

		sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
			&sciond.RevReply{Result: sciond.RevValid}, nil,
		)
		pr.Revoke(context.Background(), newTestRev(t, "1-ff00:0:130#1002"))
		assert.Len(t, sp.Load().APS, 0, "deletes the path")
	})

	t.Run("retrieves one path revoking an IFID that does not match the path", func(t *testing.T) {
		sd := mock_sciond.NewMockConnector(ctrl)
		pr := New(sd, Timers{})

		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
			buildSDAnswer(
				"1-ff00:0:111#105 1-ff00:0:130#1002 1-ff00:0:130#1004 1-ff00:0:110#2",
			), nil,
		)
		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
			buildSDAnswer(), nil,
		).AnyTimes()
		sp, err := pr.Watch(context.Background(), src, dst)
		xtest.FailOnErr(t, err)

		sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
			&sciond.RevReply{Result: sciond.RevValid}, nil,
		)
		pr.Revoke(context.Background(), newTestRev(t, "2-ff00:0:1#1"))
		assert.Len(t, sp.Load().APS, 1, "does not delete the path")
	})

	t.Run("tries to revoke an IFID, but SCIOND encounters an error", func(t *testing.T) {
		sd := mock_sciond.NewMockConnector(ctrl)
		pr := New(sd, Timers{})

		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
			buildSDAnswer(
				"1-ff00:0:111#105 1-ff00:0:130#1002 1-ff00:0:130#1004 1-ff00:0:110#2",
			), nil,
		)
		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
			buildSDAnswer(), nil,
		).AnyTimes()
		sp, err := pr.Watch(context.Background(), src, dst)
		xtest.FailOnErr(t, err)

		sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
			nil, fmt.Errorf("some error"),
		)
		pr.Revoke(context.Background(), newTestRev(t, "1-ff00:0:130#1002"))
		assert.Len(t, sp.Load().APS, 1, "does not delete the path")
	})

	t.Run("tries to revoke an IFID, but the revocation is invalid", func(t *testing.T) {
		sd := mock_sciond.NewMockConnector(ctrl)
		pr := New(sd, Timers{})

		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
			buildSDAnswer(
				"1-ff00:0:111#105 1-ff00:0:130#1002 1-ff00:0:130#1004 1-ff00:0:110#2",
			), nil,
		)
		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
			buildSDAnswer(), nil,
		).AnyTimes()
		sp, err := pr.Watch(context.Background(), src, dst)
		xtest.FailOnErr(t, err)

		sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
			&sciond.RevReply{Result: sciond.RevInvalid}, nil,
		)
		pr.Revoke(context.Background(), newTestRev(t, "1-ff00:0:130#1002"))
		assert.Len(t, sp.Load().APS, 1, "does not delete the path")
	})

	t.Run("tries to revoke an IFID, but the revocation is stale", func(t *testing.T) {
		sd := mock_sciond.NewMockConnector(ctrl)
		pr := New(sd, Timers{})

		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
			buildSDAnswer(
				"1-ff00:0:111#105 1-ff00:0:130#1002 1-ff00:0:130#1004 1-ff00:0:110#2",
			), nil,
		)
		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
			buildSDAnswer(), nil,
		).AnyTimes()
		sp, err := pr.Watch(context.Background(), src, dst)
		xtest.FailOnErr(t, err)

		sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
			&sciond.RevReply{Result: sciond.RevStale}, nil,
		)
		pr.Revoke(context.Background(), newTestRev(t, "1-ff00:0:130#1002"))
		assert.Len(t, sp.Load().APS, 1, "does not delete the path")
	})

	t.Run("tries to revoke an IFID, but the revocation is unknown", func(t *testing.T) {
		sd := mock_sciond.NewMockConnector(ctrl)
		pr := New(sd, Timers{})

		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
			buildSDAnswer(
				"1-ff00:0:111#105 1-ff00:0:130#1002 1-ff00:0:130#1004 1-ff00:0:110#2",
			), nil,
		)
		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
			buildSDAnswer(), nil,
		).AnyTimes()
		sp, err := pr.Watch(context.Background(), src, dst)
		xtest.FailOnErr(t, err)

		sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
			&sciond.RevReply{Result: sciond.RevUnknown}, nil,
		)
		pr.Revoke(context.Background(), newTestRev(t, "1-ff00:0:130#1002"))
		assert.Len(t, sp.Load().APS, 0, "deletes the path")
	})

	t.Run("retrieves two paths and revokes an IFID that matches one path", func(t *testing.T) {

		sd := mock_sciond.NewMockConnector(ctrl)
		pr := New(sd, Timers{})

		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any(), gomock.Any()).Return(
			buildSDAnswer(
				"1-ff00:0:111#105 1-ff00:0:130#1002 1-ff00:0:130#1004 1-ff00:0:110#2",
				"1-ff00:0:111#104 1-ff00:0:120#5 1-ff00:0:120#6 1-ff00:0:110#1",
			), nil,
		)
		sp, err := pr.Watch(context.Background(), src, dst)
		xtest.FailOnErr(t, err)

		sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
			&sciond.RevReply{Result: sciond.RevValid}, nil,
		)
		pr.Revoke(context.Background(), newTestRev(t, "1-ff00:0:130#1002"))
		assert.Len(t, sp.Load().APS, 1, "leaves one path remaining")
	})

}

func newTestRev(t *testing.T, rev string) *path_mgmt.SignedRevInfo {
	pi := mustParsePI(rev)
	signedRevInfo, err := path_mgmt.NewSignedRevInfo(
		&path_mgmt.RevInfo{
			IfID:     pi.IfID,
			RawIsdas: pi.RawIsdas,
		}, infra.NullSigner)
	xtest.FailOnErr(t, err)
	return signedRevInfo
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
