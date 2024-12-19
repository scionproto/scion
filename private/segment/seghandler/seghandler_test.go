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

	"github.com/scionproto/scion/pkg/private/mocks/net/mock_net"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/segment/seghandler"
	"github.com/scionproto/scion/private/segment/seghandler/mock_seghandler"
	"github.com/scionproto/scion/private/segment/segverifier"
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
		serrors.Wrap("test err 1", segverifier.ErrSegment),
		serrors.Wrap("test err 2", segverifier.ErrSegment),
		serrors.Wrap("test err 3", segverifier.ErrSegment),
	}

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
			SegMeta: &seg.Meta{},
		},
		Errors: map[int]error{-1: verifyErrs[2]},
	}
	r := handler.Handle(ctx, segs, nil)
	assert.Error(t, r.Err())
	assert.Len(t, r.VerificationErrors(), len(verifyErrs))
	stats := r.Stats()
	assert.Zero(t, len(stats.VerifiedSegs))
	assert.Zero(t, stats.SegsUpdated())
	assert.Zero(t, stats.SegsInserted())
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
			SegMeta: seg3,
		},
	}
	r := handler.Handle(ctx, segs, nil)
	assert.NoError(t, r.Err())
	assert.Nil(t, r.VerificationErrors())
	stats := r.Stats()
	assert.Equal(t, 3, len(stats.VerifiedSegs))
	assert.Equal(t, 3, stats.SegsInserted())
	assert.Zero(t, stats.SegsUpdated())
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
}
