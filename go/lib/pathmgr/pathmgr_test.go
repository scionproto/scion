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

package pathmgr_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/pathmgr/mock_pathmgr"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/sciond/mock_sciond"
	"github.com/scionproto/scion/go/lib/xtest"
)

const timeUnitDuration time.Duration = 10 * time.Millisecond

func getDuration(units time.Duration) time.Duration {
	return units * timeUnitDuration
}

func TestQuery(t *testing.T) {
	t.Log("Query")
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sd := mock_sciond.NewMockConnector(ctrl)
	pm := pathmgr.New(sd, pathmgr.Timers{})

	srcIA, dstIA := xtest.MustParseIA("1-ff00:0:133"), xtest.MustParseIA("1-ff00:0:131")

	paths := []string{}

	f := func(t *testing.T, p string) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		t.Log("get")
		paths = append(paths, p)
		sdAnswer := buildSDAnswer(t, ctrl, paths...)
		sd.EXPECT().Paths(gomock.Any(), dstIA, srcIA, gomock.Any()).Return(
			sdAnswer, nil,
		)
		aps := pm.Query(context.Background(), srcIA, dstIA, sciond.PathReqFlags{})
		assert.Len(t, aps, len(paths), fmt.Sprintf("get %d paths", len(paths)))
		// TODO(lukedirtwalker): optimally we should also check contents but
		// mocked paths are not comparable.
	}

	pathOne := fmt.Sprintf("%s#1019 1-ff00:0:132#1910 1-ff00:0:132#1916 %s#1619", srcIA, dstIA)
	t.Run("pathOne", func(t *testing.T) {
		f(t, pathOne)
	})
	pathTwo := fmt.Sprintf("%s#101902 1-ff00:0:132#191002 1-ff00:0:132#1916 %s#1619", srcIA, dstIA)
	t.Run("pathTwo", func(t *testing.T) {
		f(t, pathTwo)
	})
}

func TestQueryFilter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sd := mock_sciond.NewMockConnector(ctrl)
	pm := pathmgr.New(sd, pathmgr.Timers{})

	srcIA := xtest.MustParseIA("1-ff00:0:133")
	dstIA := xtest.MustParseIA("1-ff00:0:131")

	pathOne := fmt.Sprintf("%s#1019 1-ff00:0:132#1910 1-ff00:0:132#1916 %s#1619", srcIA, dstIA)
	paths := []string{pathOne}

	sd.EXPECT().Paths(gomock.Any(), dstIA, srcIA, gomock.Any()).Return(
		buildSDAnswer(t, ctrl, paths...), nil,
	).AnyTimes()

	tests := map[string]struct {
		Policy        func(ctrl *gomock.Controller) pathmgr.Policy
		ExpectedPaths int
	}{
		"Nil policy": {
			Policy: func(_ *gomock.Controller) pathmgr.Policy {
				return nil
			},
			ExpectedPaths: 1,
		},
		"Deny policy": {
			Policy: func(ctrl *gomock.Controller) pathmgr.Policy {
				pol := mock_pathmgr.NewMockPolicy(ctrl)
				pol.EXPECT().Filter(gomock.Any()).Return(make(pathpol.PathSet))
				return pol
			},
			ExpectedPaths: 0,
		},
		"Accept policy": {
			Policy: func(_ *gomock.Controller) pathmgr.Policy {
				pol := mock_pathmgr.NewMockPolicy(ctrl)
				pol.EXPECT().Filter(gomock.Any()).DoAndReturn(
					func(ps pathpol.PathSet) pathpol.PathSet {
						return ps
					},
				)
				return pol
			},
			ExpectedPaths: 1,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			aps := pm.QueryFilter(context.Background(), srcIA, dstIA, test.Policy(ctrl))
			assert.Len(t, aps, test.ExpectedPaths)
			// TODO(lukedirtwalker): optimally we should also check contents but
			// mocked paths are not comparable.
			// if test.ExpectedPaths > 0 {
			// 	assert.ElementsMatch(t, getPathStrings(aps), paths)
			// }
		})
	}
}

func TestWatchCount(t *testing.T) {
	t.Log("Given a path manager and adding a watch")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sd := mock_sciond.NewMockConnector(ctrl)
	pr := pathmgr.New(sd, pathmgr.Timers{})

	src := xtest.MustParseIA("1-ff00:0:111")
	dst := xtest.MustParseIA("1-ff00:0:110")

	sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any()).AnyTimes()

	assert.Equal(t, pr.WatchCount(), 0, " the count is initially 0")
	sp, err := pr.Watch(context.Background(), src, dst)
	require.NoError(t, err)
	assert.Equal(t, pr.WatchCount(), 1, "the number of watches increases to 1")
	sp.Destroy()
	assert.Equal(t, pr.WatchCount(), 0, "the number of watches decreases to 0")
}

func TestWatchPolling(t *testing.T) {
	t.Log("Given a path manager and adding a watch that retrieves zero paths")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sd := mock_sciond.NewMockConnector(ctrl)
	pr := pathmgr.New(sd, pathmgr.Timers{ErrorRefire: getDuration(1)})

	src := xtest.MustParseIA("1-ff00:0:111")
	dst := xtest.MustParseIA("1-ff00:0:110")
	gomock.InOrder(
		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any()),
		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any()).Return(
			buildSDAnswer(t, ctrl,
				"1-ff00:0:111#105 1-ff00:0:130#1002 1-ff00:0:130#1004 1-ff00:0:110#2",
			), nil,
		).MinTimes(1),
	)

	sp, err := pr.Watch(context.Background(), src, dst)
	require.NoError(t, err)
	assert.Len(t, sp.Load().APS, 0, "there are 0 paths currently available")
	time.Sleep(getDuration(4))
	assert.Len(t, sp.Load().APS, 1, "and after waiting, we get pathmgr.New paths")
}

func TestWatchFilter(t *testing.T) {
	t.Log("Given a path manager and adding a watch that should retrieve 1 path")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	sd := mock_sciond.NewMockConnector(ctrl)
	pr := pathmgr.New(sd, pathmgr.Timers{ErrorRefire: getDuration(1)})

	src := xtest.MustParseIA("1-ff00:0:111")
	dst := xtest.MustParseIA("1-ff00:0:110")
	gomock.InOrder(
		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any()).Return(
			buildSDAnswer(t, ctrl,
				"1-ff00:0:111#104 1-ff00:0:120#5 1-ff00:0:120#6 1-ff00:0:110#1",
			), nil,
		),
		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any()).Return(
			buildSDAnswer(t, ctrl,
				"1-ff00:0:111#105 1-ff00:0:130#1002 1-ff00:0:130#1004 1-ff00:0:110#2",
				"1-ff00:0:111#104 1-ff00:0:120#5 1-ff00:0:120#6 1-ff00:0:110#1",
			), nil,
		).AnyTimes(),
	)

	policy := mock_pathmgr.NewMockPolicy(ctrl)
	policy.EXPECT().Filter(gomock.Any()).DoAndReturn(
		func(ps pathpol.PathSet) pathpol.PathSet {
			replySet := make(pathpol.PathSet)
			for key, v := range ps {
				for _, intf := range v.Interfaces() {
					if intf.IA.Equal(src) && intf.ID == 105 {
						replySet[key] = v
						break
					}
				}
			}
			return replySet
		},
	).AnyTimes()

	sp, err := pr.WatchFilter(context.Background(), src, dst, policy)
	require.NoError(t, err)
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
	pr := pathmgr.New(sd, pathmgr.Timers{
		NormalRefire: getDuration(100),
		ErrorRefire:  getDuration(1),
	})

	sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any()).Return(
		buildSDAnswer(t, ctrl,
			"1-ff00:0:111#105 1-ff00:0:130#1002 1-ff00:0:130#1004 1-ff00:0:110#2",
		), nil,
	)

	_, err := pr.Watch(context.Background(), src, dst)
	require.NoError(t, err)

	// Once everything is revoked a fast request is immediately
	// triggered. We check for at least 2 iterations to make sure we
	// are in error recovery mode, and the aggressive timer is used.
	// We actually test that the mock .{Revnotifications,Paths} functions are
	// being called within a 5 time units. It will fail with "missing
	// call(s)" error message
	gomock.InOrder(
		sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
			nil,
		),
		sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any()).MinTimes(2),
	)
	pr.Revoke(context.Background(), NewTestRev(t, xtest.MustParseIA("1-ff00:0:130"), 1002))
	time.Sleep(getDuration(5))
}

func TestRevoke(t *testing.T) {
	t.Log("Given a path manager and a watch that")

	src := xtest.MustParseIA("1-ff00:0:111")
	dst := xtest.MustParseIA("1-ff00:0:110")
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	paths := []string{
		"1-ff00:0:111#105 1-ff00:0:130#1002 1-ff00:0:130#1004 1-ff00:0:110#2",
		"1-ff00:0:111#104 1-ff00:0:120#5 1-ff00:0:120#6 1-ff00:0:110#1",
	}

	tests := map[string]struct {
		Paths         []string
		RevReplyError error
		Revocation    *path_mgmt.SignedRevInfo
		Remaining     int
	}{
		"retrieves one path, revokes an IFID that matches the path": {
			Paths:      paths[:1],
			Revocation: NewTestRev(t, xtest.MustParseIA("1-ff00:0:130"), 1002),
			Remaining:  0,
		},
		"tries to revoke an IFID, but SCIOND encounters an error": {
			Paths:         paths[:1],
			RevReplyError: errors.New("some error"),
			Revocation:    NewTestRev(t, xtest.MustParseIA("1-ff00:0:130"), 1002),
			Remaining:     1,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			sd := mock_sciond.NewMockConnector(ctrl)
			pr := pathmgr.New(sd, pathmgr.Timers{})

			sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any()).Return(
				buildSDAnswer(t, ctrl, test.Paths...), nil,
			)
			sd.EXPECT().Paths(gomock.Any(), dst, src, gomock.Any()).AnyTimes()
			sp, err := pr.Watch(context.Background(), src, dst)
			require.NoError(t, err)
			sd.EXPECT().RevNotification(gomock.Any(), gomock.Any()).Return(
				test.RevReplyError,
			)
			pr.Revoke(context.Background(), test.Revocation)
			assert.Len(t, sp.Load().APS, test.Remaining)
		})
	}

}

func NewTestRev(t *testing.T, ia addr.IA, ifID common.IFIDType) *path_mgmt.SignedRevInfo {
	signedRevInfo, err := path_mgmt.NewSignedRevInfo(
		&path_mgmt.RevInfo{
			IfID:     ifID,
			RawIsdas: ia.IAInt(),
		}, infra.NullSigner)
	require.NoError(t, err)
	return signedRevInfo
}
