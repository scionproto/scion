// Copyright 2019 Anapaya Systems
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

package seghandler_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler/mock_seghandler"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/mocks/net/mock_net"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

var TestTimeout = time.Second

// TestReplyHandlerEmptyReply test that we can handle an empty SegReply.
func TestReplyHandlerEmptyReply(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx, cancelF := context.WithTimeout(context.Background(), TestTimeout)
	defer cancelF()

	segs := seghandler.Segments{}
	earlyTrigger := make(chan struct{})
	verified := make(chan segverifier.UnitResult)
	close(verified)

	server := mock_net.NewMockAddr(ctrl)
	storage := mock_seghandler.NewMockStorage(ctrl)
	verifier := mock_seghandler.NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(ctx, segs, gomock.Eq(server)).Return(verified, 0)
	handler := seghandler.Handler{
		Storage:  storage,
		Verifier: verifier,
	}

	r := handler.Handle(ctx, segs, server, earlyTrigger)
	AssertRead(t, r.EarlyTriggerProcessed(), 0, time.Second/2)
	xtest.AssertReadReturnsBefore(t, r.FullReplyProcessed(), time.Second/2)
	assert.NoError(t, r.Err())
	assert.Nil(t, r.VerificationErrors())
	stats := r.Stats()
	assert.Zero(t, stats.VerifiedSegs)
	assert.Zero(t, stats.SegDB.Total())
	assert.Empty(t, stats.VerifiedRevs)
	assert.Empty(t, stats.StoredRevs)
}

// TestReplyHandlerErrors tests erros that happen during verification are
// properly stored in the result struct.
func TestReplyHandlerErrors(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx, cancelF := context.WithTimeout(context.Background(), TestTimeout)
	defer cancelF()

	segs := seghandler.Segments{}
	earlyTrigger := make(chan struct{})
	verified := make(chan segverifier.UnitResult)

	verifyErrs := []error{
		common.NewBasicError("test err 1", nil),
		common.NewBasicError("test err 2", nil),
		common.NewBasicError("test err 3", nil),
		common.NewBasicError("test err rev 1", nil),
	}
	rev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{}, infra.NullSigner)
	xtest.FailOnErr(t, err)

	storage := mock_seghandler.NewMockStorage(ctrl)
	verifier := mock_seghandler.NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(ctx, segs, gomock.Any()).Return(verified, 3)
	handler := seghandler.Handler{
		Storage:  storage,
		Verifier: verifier,
	}
	r := handler.Handle(ctx, segs, nil, earlyTrigger)
	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta: &seg.Meta{},
		},
		Errors: map[int]error{-1: verifyErrs[0]},
	}
	close(earlyTrigger)
	AssertRead(t, r.EarlyTriggerProcessed(), 0, time.Second/2)
	AssertChanEmpty(t, r.FullReplyProcessed())
	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta: &seg.Meta{},
		},
		Errors: map[int]error{-1: verifyErrs[1]},
	}
	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta:   &seg.Meta{},
			SRevInfos: []*path_mgmt.SignedRevInfo{rev1},
		},
		Errors: map[int]error{-1: verifyErrs[2], 0: verifyErrs[3]},
	}
	xtest.AssertReadReturnsBefore(t, r.FullReplyProcessed(), time.Second/2)
	assert.NoError(t, r.Err())
	assert.Len(t, r.VerificationErrors(), len(verifyErrs))
	stats := r.Stats()
	assert.Zero(t, stats.VerifiedSegs)
	assert.Zero(t, stats.SegDB.Total())
	assert.Empty(t, stats.VerifiedRevs)
	assert.Empty(t, stats.StoredRevs)
}

// TestReplyHandlerNoErrors tests the happy case of the reply handler: 3
// segments and 1 revocation are successfully verified and stored.
func TestReplyHandlerNoErrors(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx, cancelF := context.WithTimeout(context.Background(), TestTimeout)
	defer cancelF()

	seg1 := &seghandler.SegWithHP{
		Seg: &seg.Meta{Type: proto.PathSegType_down},
	}
	seg2 := &seghandler.SegWithHP{
		Seg: &seg.Meta{Type: proto.PathSegType_up},
	}
	seg3 := &seghandler.SegWithHP{
		Seg: &seg.Meta{Type: proto.PathSegType_core},
	}
	rev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{}, infra.NullSigner)
	xtest.FailOnErr(t, err)
	segs := seghandler.Segments{}
	earlyTrigger := make(chan struct{})
	verified := make(chan segverifier.UnitResult)

	storage := mock_seghandler.NewMockStorage(ctrl)
	verifier := mock_seghandler.NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(ctx, segs, gomock.Any()).Return(verified, 3)
	handler := seghandler.Handler{
		Storage:  storage,
		Verifier: verifier,
	}
	seg1Store := storage.EXPECT().StoreSegs(gomock.Any(),
		gomock.Eq([]*seghandler.SegWithHP{seg1})).
		Return(seghandler.SegStats{InsertedSegs: []string{"seg1"}}, nil)
	storage.EXPECT().StoreSegs(gomock.Any(),
		gomock.Eq([]*seghandler.SegWithHP{seg2, seg3})).
		Return(seghandler.SegStats{InsertedSegs: []string{"seg2", "seg3"}}, nil).
		After(seg1Store)
	storage.EXPECT().StoreRevs(gomock.Any(),
		gomock.Eq([]*path_mgmt.SignedRevInfo{rev1})).After(seg1Store)

	r := handler.Handle(ctx, segs, nil, earlyTrigger)
	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta: seg1.Seg,
		},
	}
	close(earlyTrigger)
	AssertRead(t, r.EarlyTriggerProcessed(), 1, time.Second/2)
	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta: seg2.Seg,
		},
	}
	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta:   seg3.Seg,
			SRevInfos: []*path_mgmt.SignedRevInfo{rev1},
		},
	}
	xtest.AssertReadReturnsBefore(t, r.FullReplyProcessed(), time.Second/2)
	assert.NoError(t, r.Err())
	assert.Nil(t, r.VerificationErrors())
	stats := r.Stats()
	assert.Equal(t, 3, stats.VerifiedSegs)
	assert.Equal(t, 3, stats.SegDB.Total())
	expectedRevs := []*path_mgmt.SignedRevInfo{rev1}
	assert.ElementsMatch(t, expectedRevs, stats.VerifiedRevs)
	assert.ElementsMatch(t, expectedRevs, stats.StoredRevs)
}

func TestReplyHandlerAllVerifiedInEarlyInterval(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx, cancelF := context.WithTimeout(context.Background(), TestTimeout)
	defer cancelF()

	seg1 := &seghandler.SegWithHP{
		Seg: &seg.Meta{Type: proto.PathSegType_down},
	}
	seg2 := &seghandler.SegWithHP{
		Seg: &seg.Meta{Type: proto.PathSegType_up},
	}
	rev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{}, infra.NullSigner)
	xtest.FailOnErr(t, err)
	segs := seghandler.Segments{}
	earlyTrigger := make(chan struct{})
	verified := make(chan segverifier.UnitResult)

	storage := mock_seghandler.NewMockStorage(ctrl)
	verifier := mock_seghandler.NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(ctx, segs, gomock.Any()).Return(verified, 2)
	handler := seghandler.Handler{
		Storage:  storage,
		Verifier: verifier,
	}
	storage.EXPECT().StoreSegs(gomock.Any(),
		gomock.Eq([]*seghandler.SegWithHP{seg1, seg2})).
		Return(seghandler.SegStats{InsertedSegs: []string{"seg1", "seg2"}}, nil)
	storage.EXPECT().StoreRevs(gomock.Any(),
		gomock.Eq([]*path_mgmt.SignedRevInfo{rev1}))

	r := handler.Handle(ctx, segs, nil, earlyTrigger)
	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta: seg1.Seg,
		},
	}
	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta:   seg2.Seg,
			SRevInfos: []*path_mgmt.SignedRevInfo{rev1},
		},
	}
	AssertRead(t, r.EarlyTriggerProcessed(), 2, time.Second/2)
	xtest.AssertReadReturnsBefore(t, r.FullReplyProcessed(), time.Second/2)
	assert.NoError(t, r.Err())
	assert.Nil(t, r.VerificationErrors())
	stats := r.Stats()
	assert.Equal(t, 2, stats.VerifiedSegs)
	assert.Equal(t, 2, stats.SegDB.Total())
	expectedRevs := []*path_mgmt.SignedRevInfo{rev1}
	assert.ElementsMatch(t, expectedRevs, stats.VerifiedRevs)
	assert.ElementsMatch(t, expectedRevs, stats.StoredRevs)
}

func TestReplyHandlerEarlyTriggerStorageError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx, cancelF := context.WithTimeout(context.Background(), TestTimeout)
	defer cancelF()

	seg1 := &seghandler.SegWithHP{
		Seg: &seg.Meta{Type: proto.PathSegType_down},
	}
	seg2 := &seghandler.SegWithHP{
		Seg: &seg.Meta{Type: proto.PathSegType_up},
	}
	rev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{}, infra.NullSigner)
	xtest.FailOnErr(t, err)
	segs := seghandler.Segments{}
	earlyTrigger := make(chan struct{})
	verified := make(chan segverifier.UnitResult)

	storage := mock_seghandler.NewMockStorage(ctrl)
	verifier := mock_seghandler.NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(ctx, segs, gomock.Any()).Return(verified, 2)
	handler := seghandler.Handler{
		Storage:  storage,
		Verifier: verifier,
	}
	seg1Store := storage.EXPECT().StoreSegs(gomock.Any(),
		gomock.Eq([]*seghandler.SegWithHP{seg1})).
		Return(seghandler.SegStats{}, common.NewBasicError("Test error", nil))
	storage.EXPECT().StoreSegs(gomock.Any(),
		gomock.Eq([]*seghandler.SegWithHP{seg1, seg2})).
		Return(seghandler.SegStats{InsertedSegs: []string{"seg1", "seg2"}}, nil).
		After(seg1Store)
	storage.EXPECT().StoreRevs(gomock.Any(),
		gomock.Eq([]*path_mgmt.SignedRevInfo{rev1}))

	r := handler.Handle(ctx, segs, nil, earlyTrigger)
	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta: seg1.Seg,
		},
	}
	close(earlyTrigger)
	AssertRead(t, r.EarlyTriggerProcessed(), 0, time.Second/2)
	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta:   seg2.Seg,
			SRevInfos: []*path_mgmt.SignedRevInfo{rev1},
		},
	}
	xtest.AssertReadReturnsBefore(t, r.FullReplyProcessed(), time.Second/2)
	assert.NoError(t, r.Err())
	assert.Nil(t, r.VerificationErrors())

	stats := r.Stats()
	assert.Equal(t, 2, stats.VerifiedSegs)
	assert.Equal(t, 2, stats.SegDB.Total())
	expectedRevs := []*path_mgmt.SignedRevInfo{rev1}
	assert.ElementsMatch(t, expectedRevs, stats.VerifiedRevs)
	assert.ElementsMatch(t, expectedRevs, stats.StoredRevs)
}

func TestReplyHandlerStorageError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx, cancelF := context.WithTimeout(context.Background(), TestTimeout)
	defer cancelF()

	seg1 := &seghandler.SegWithHP{
		Seg: &seg.Meta{Type: proto.PathSegType_down},
	}
	seg2 := &seghandler.SegWithHP{
		Seg: &seg.Meta{Type: proto.PathSegType_up},
	}
	segs := seghandler.Segments{}
	earlyTrigger := make(chan struct{})
	verified := make(chan segverifier.UnitResult)

	storage := mock_seghandler.NewMockStorage(ctrl)
	verifier := mock_seghandler.NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(ctx, segs, gomock.Any()).Return(verified, 2)
	handler := seghandler.Handler{
		Storage:  storage,
		Verifier: verifier,
	}
	storageErr := common.NewBasicError("Test error", nil)
	storage.EXPECT().StoreSegs(gomock.Any(),
		gomock.Eq([]*seghandler.SegWithHP{seg1, seg2})).
		Return(seghandler.SegStats{}, storageErr)

	close(earlyTrigger)
	r := handler.Handle(ctx, segs, nil, earlyTrigger)
	AssertRead(t, r.EarlyTriggerProcessed(), 0, time.Second/2)
	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta: seg1.Seg,
		},
	}
	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta: seg2.Seg,
		},
	}
	xtest.AssertReadReturnsBefore(t, r.FullReplyProcessed(), time.Second/2)
	assert.Error(t, r.Err())
	assert.Nil(t, r.VerificationErrors())
	stats := r.Stats()
	assert.Equal(t, 2, stats.VerifiedSegs)
	assert.Zero(t, stats.SegDB.Total())
	assert.Empty(t, stats.VerifiedRevs)
	assert.Empty(t, stats.StoredRevs)
}

func AssertChanEmpty(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("Expected channel to be empty but was not")
	default:
	}
}

func AssertRead(t *testing.T, ch <-chan int, expected int, timeout time.Duration) {
	t.Helper()
	select {
	case res := <-ch:
		assert.Equal(t, expected, res, "Wrong result in channel")
	case <-time.After(timeout):
		t.Fatalf("Timed out while waiting for channel result")
	}
}
