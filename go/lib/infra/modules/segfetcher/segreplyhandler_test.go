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

package segfetcher_test

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
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher/mock_segfetcher"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/mocks/net/mock_net"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

var TestTimeout = time.Second

func TestReplyHandlerEmptyReply(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx, cancelF := context.WithTimeout(context.Background(), TestTimeout)
	defer cancelF()

	reply := &path_mgmt.SegReply{}
	earlyTrigger := make(chan struct{})
	verified := make(chan segverifier.UnitResult)
	close(verified)

	server := mock_net.NewMockAddr(ctrl)
	storage := mock_segfetcher.NewMockStorage(ctrl)
	verifier := mock_segfetcher.NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(ctx, reply, gomock.Eq(server)).Return(verified, 0)
	handler := segfetcher.SegReplyHandler{
		Storage:  storage,
		Verifier: verifier,
	}

	r := handler.Handle(ctx, reply, server, earlyTrigger)
	AssertRead(t, r.EarlyTriggerProcessed(), 0, time.Second/2)
	xtest.AssertReadReturnsBefore(t, r.FullReplyProcessed(), time.Second/2)
	assert.NoError(t, r.Err())
	assert.Nil(t, r.VerificationErrors())
}

func TestReplyHandlerErrors(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx, cancelF := context.WithTimeout(context.Background(), TestTimeout)
	defer cancelF()

	reply := &path_mgmt.SegReply{}
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

	storage := mock_segfetcher.NewMockStorage(ctrl)
	verifier := mock_segfetcher.NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(ctx, reply, gomock.Any()).Return(verified, 3)
	handler := segfetcher.SegReplyHandler{
		Storage:  storage,
		Verifier: verifier,
	}
	r := handler.Handle(ctx, reply, nil, earlyTrigger)
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
}

func TestReplyHandlerNoErrors(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx, cancelF := context.WithTimeout(context.Background(), TestTimeout)
	defer cancelF()

	seg1 := &segfetcher.SegWithHP{
		Seg:      &seg.Meta{Type: proto.PathSegType_down},
		HPCfgIds: []*query.HPCfgID{&query.NullHpCfgID},
	}
	seg2 := &segfetcher.SegWithHP{
		Seg:      &seg.Meta{Type: proto.PathSegType_up},
		HPCfgIds: []*query.HPCfgID{&query.NullHpCfgID},
	}
	seg3 := &segfetcher.SegWithHP{
		Seg:      &seg.Meta{Type: proto.PathSegType_core},
		HPCfgIds: []*query.HPCfgID{&query.NullHpCfgID},
	}
	rev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{}, infra.NullSigner)
	xtest.FailOnErr(t, err)
	reply := &path_mgmt.SegReply{}
	earlyTrigger := make(chan struct{})
	verified := make(chan segverifier.UnitResult)

	storage := mock_segfetcher.NewMockStorage(ctrl)
	verifier := mock_segfetcher.NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(ctx, reply, gomock.Any()).Return(verified, 3)
	handler := segfetcher.SegReplyHandler{
		Storage:  storage,
		Verifier: verifier,
	}
	seg1Store := storage.EXPECT().StoreSegs(gomock.Any(),
		gomock.Eq([]*segfetcher.SegWithHP{seg1}))
	storage.EXPECT().StoreSegs(gomock.Any(),
		gomock.Eq([]*segfetcher.SegWithHP{seg2, seg3})).After(seg1Store)
	storage.EXPECT().StoreRevs(gomock.Any(),
		gomock.Eq([]*path_mgmt.SignedRevInfo{rev1})).After(seg1Store)

	r := handler.Handle(ctx, reply, nil, earlyTrigger)
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
}

func TestReplyHandlerAllVerifiedInEarlyInterval(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx, cancelF := context.WithTimeout(context.Background(), TestTimeout)
	defer cancelF()

	seg1 := &segfetcher.SegWithHP{
		Seg:      &seg.Meta{Type: proto.PathSegType_down},
		HPCfgIds: []*query.HPCfgID{&query.NullHpCfgID},
	}
	seg2 := &segfetcher.SegWithHP{
		Seg:      &seg.Meta{Type: proto.PathSegType_up},
		HPCfgIds: []*query.HPCfgID{&query.NullHpCfgID},
	}
	rev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{}, infra.NullSigner)
	xtest.FailOnErr(t, err)
	reply := &path_mgmt.SegReply{}
	earlyTrigger := make(chan struct{})
	verified := make(chan segverifier.UnitResult)

	storage := mock_segfetcher.NewMockStorage(ctrl)
	verifier := mock_segfetcher.NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(ctx, reply, gomock.Any()).Return(verified, 2)
	handler := segfetcher.SegReplyHandler{
		Storage:  storage,
		Verifier: verifier,
	}
	storage.EXPECT().StoreSegs(gomock.Any(),
		gomock.Eq([]*segfetcher.SegWithHP{seg1, seg2}))
	storage.EXPECT().StoreRevs(gomock.Any(),
		gomock.Eq([]*path_mgmt.SignedRevInfo{rev1}))

	r := handler.Handle(ctx, reply, nil, earlyTrigger)
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
}

func TestReplyHandlerEarlyTriggerStorageError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx, cancelF := context.WithTimeout(context.Background(), TestTimeout)
	defer cancelF()

	seg1 := &segfetcher.SegWithHP{
		Seg:      &seg.Meta{Type: proto.PathSegType_down},
		HPCfgIds: []*query.HPCfgID{&query.NullHpCfgID},
	}
	seg2 := &segfetcher.SegWithHP{
		Seg:      &seg.Meta{Type: proto.PathSegType_up},
		HPCfgIds: []*query.HPCfgID{&query.NullHpCfgID},
	}
	rev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{}, infra.NullSigner)
	xtest.FailOnErr(t, err)
	reply := &path_mgmt.SegReply{}
	earlyTrigger := make(chan struct{})
	verified := make(chan segverifier.UnitResult)

	storage := mock_segfetcher.NewMockStorage(ctrl)
	verifier := mock_segfetcher.NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(ctx, reply, gomock.Any()).Return(verified, 2)
	handler := segfetcher.SegReplyHandler{
		Storage:  storage,
		Verifier: verifier,
	}
	seg1Store := storage.EXPECT().StoreSegs(gomock.Any(),
		gomock.Eq([]*segfetcher.SegWithHP{seg1})).
		Return(common.NewBasicError("Test error", nil))
	storage.EXPECT().StoreSegs(gomock.Any(),
		gomock.Eq([]*segfetcher.SegWithHP{seg1, seg2})).After(seg1Store)
	storage.EXPECT().StoreRevs(gomock.Any(),
		gomock.Eq([]*path_mgmt.SignedRevInfo{rev1}))

	r := handler.Handle(ctx, reply, nil, earlyTrigger)
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
}

func TestReplyHandlerStorageError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx, cancelF := context.WithTimeout(context.Background(), TestTimeout)
	defer cancelF()

	seg1 := &segfetcher.SegWithHP{
		Seg:      &seg.Meta{Type: proto.PathSegType_down},
		HPCfgIds: []*query.HPCfgID{&query.NullHpCfgID},
	}
	seg2 := &segfetcher.SegWithHP{
		Seg:      &seg.Meta{Type: proto.PathSegType_up},
		HPCfgIds: []*query.HPCfgID{&query.NullHpCfgID},
	}
	reply := &path_mgmt.SegReply{}
	earlyTrigger := make(chan struct{})
	verified := make(chan segverifier.UnitResult)

	storage := mock_segfetcher.NewMockStorage(ctrl)
	verifier := mock_segfetcher.NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(ctx, reply, gomock.Any()).Return(verified, 2)
	handler := segfetcher.SegReplyHandler{
		Storage:  storage,
		Verifier: verifier,
	}
	storageErr := common.NewBasicError("Test error", nil)
	storage.EXPECT().StoreSegs(gomock.Any(),
		gomock.Eq([]*segfetcher.SegWithHP{seg1, seg2})).
		Return(storageErr)

	close(earlyTrigger)
	r := handler.Handle(ctx, reply, nil, earlyTrigger)
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
