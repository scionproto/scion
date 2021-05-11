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

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler/mock_seghandler"
	"github.com/scionproto/scion/go/lib/infra/modules/segverifier"
	"github.com/scionproto/scion/go/lib/mocks/net/mock_net"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
)

var TestTimeout = time.Second

// TestReplyHandlerEmptyReply test that we can handle an empty SegReply.
func TestReplyHandlerEmptyReply(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx, cancelF := context.WithTimeout(context.Background(), TestTimeout)
	defer cancelF()

	segs := seghandler.Segments{}
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

	r := handler.Handle(ctx, segs, server)
	assert.NoError(t, r.Err())
	assert.Nil(t, r.VerificationErrors())
	stats := r.Stats()
	assert.Zero(t, len(stats.VerifiedSegs))
	assert.Zero(t, stats.SegsUpdated())
	assert.Zero(t, stats.SegsInserted())
	assert.Empty(t, stats.VerifiedRevs)
	assert.Empty(t, stats.StoredRevs)
}

// TestHandleAllVerificationsFail tests erros that happen during verification
// are properly stored in the result struct and that the result sets the Err.
func TestHandleAllVerificationsFail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx, cancelF := context.WithTimeout(context.Background(), TestTimeout)
	defer cancelF()

	segs := seghandler.Segments{}
	verified := make(chan segverifier.UnitResult, 3)

	verifyErrs := []error{
		serrors.WrapStr("test err 1", segverifier.ErrSegment),
		serrors.WrapStr("test err 2", segverifier.ErrSegment),
		serrors.WrapStr("test err 3", segverifier.ErrSegment),
		serrors.WrapStr("test err rev 1", segverifier.ErrRevocation),
	}
	rev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{})
	xtest.FailOnErr(t, err)

	storage := mock_seghandler.NewMockStorage(ctrl)
	verifier := mock_seghandler.NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(ctx, segs, gomock.Any()).Return(verified, 3)
	handler := seghandler.Handler{
		Storage:  storage,
		Verifier: verifier,
	}
	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta: &seg.Meta{},
		},
		Errors: map[int]error{-1: verifyErrs[0]},
	}
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
	r := handler.Handle(ctx, segs, nil)
	assert.Error(t, r.Err())
	assert.Len(t, r.VerificationErrors(), len(verifyErrs))
	stats := r.Stats()
	assert.Zero(t, len(stats.VerifiedSegs))
	assert.Zero(t, stats.SegsUpdated())
	assert.Zero(t, stats.SegsInserted())
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

	seg1 := &seg.Meta{Type: seg.TypeDown}
	seg2 := &seg.Meta{Type: seg.TypeUp}
	seg3 := &seg.Meta{Type: seg.TypeCore}
	rev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{})
	xtest.FailOnErr(t, err)
	segs := seghandler.Segments{}
	verified := make(chan segverifier.UnitResult, 3)

	storage := mock_seghandler.NewMockStorage(ctrl)
	verifier := mock_seghandler.NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(ctx, segs, gomock.Any()).Return(verified, 3)
	handler := seghandler.Handler{
		Storage:  storage,
		Verifier: verifier,
	}
	storage.EXPECT().StoreSegs(gomock.Any(),
		gomock.Eq([]*seg.Meta{seg1, seg2, seg3})).
		Return(seghandler.SegStats{InsertedSegs: []string{"seg1", "seg2", "seg3"}}, nil)
	storage.EXPECT().StoreRevs(gomock.Any(),
		gomock.Eq([]*path_mgmt.SignedRevInfo{rev1}))

	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta: seg1,
		},
	}
	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta: seg2,
		},
	}
	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta:   seg3,
			SRevInfos: []*path_mgmt.SignedRevInfo{rev1},
		},
	}
	r := handler.Handle(ctx, segs, nil)
	assert.NoError(t, r.Err())
	assert.Nil(t, r.VerificationErrors())
	stats := r.Stats()
	assert.Equal(t, 3, len(stats.VerifiedSegs))
	assert.Equal(t, 3, stats.SegsInserted())
	assert.Zero(t, stats.SegsUpdated())
	expectedRevs := []*path_mgmt.SignedRevInfo{rev1}
	assert.ElementsMatch(t, expectedRevs, stats.VerifiedRevs)
	assert.ElementsMatch(t, expectedRevs, stats.StoredRevs)
}

func TestReplyHandlerStorageError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx, cancelF := context.WithTimeout(context.Background(), TestTimeout)
	defer cancelF()

	seg1 := &seg.Meta{Type: seg.TypeDown}
	seg2 := &seg.Meta{Type: seg.TypeUp}
	segs := seghandler.Segments{}
	verified := make(chan segverifier.UnitResult, 2)

	storage := mock_seghandler.NewMockStorage(ctrl)
	verifier := mock_seghandler.NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(ctx, segs, gomock.Any()).Return(verified, 2)
	handler := seghandler.Handler{
		Storage:  storage,
		Verifier: verifier,
	}
	storageErr := serrors.New("Test error")
	storage.EXPECT().StoreSegs(gomock.Any(),
		gomock.Eq([]*seg.Meta{seg1, seg2})).
		Return(seghandler.SegStats{}, storageErr)

	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta: seg1,
		},
	}
	verified <- segverifier.UnitResult{
		Unit: &segverifier.Unit{
			SegMeta: seg2,
		},
	}
	r := handler.Handle(ctx, segs, nil)
	assert.Error(t, r.Err())
	assert.Nil(t, r.VerificationErrors())
	stats := r.Stats()
	assert.Equal(t, 2, len(stats.VerifiedSegs))
	assert.Zero(t, stats.SegsUpdated())
	assert.Zero(t, stats.SegsInserted())
	assert.Empty(t, stats.VerifiedRevs)
	assert.Empty(t, stats.StoredRevs)
}
