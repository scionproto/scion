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
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher/mock_segfetcher"
	"github.com/scionproto/scion/go/lib/pathdb/mock_pathdb"
)

type TestableFetcher struct {
	Validator     *mock_segfetcher.MockValidator
	Splitter      *mock_segfetcher.MockSplitter
	Resolver      *mock_segfetcher.MockResolver
	Requester     *mock_segfetcher.MockRequester
	ReplyHandler  *mock_segfetcher.MockReplyHandler
	PathDB        *mock_pathdb.MockPathDB
	QueryInterval time.Duration
}

func NewTestFetcher(ctrl *gomock.Controller) *TestableFetcher {
	return &TestableFetcher{
		Validator:     mock_segfetcher.NewMockValidator(ctrl),
		Splitter:      mock_segfetcher.NewMockSplitter(ctrl),
		Resolver:      mock_segfetcher.NewMockResolver(ctrl),
		Requester:     mock_segfetcher.NewMockRequester(ctrl),
		ReplyHandler:  mock_segfetcher.NewMockReplyHandler(ctrl),
		PathDB:        mock_pathdb.NewMockPathDB(ctrl),
		QueryInterval: time.Minute,
	}
}

func (f *TestableFetcher) Fetcher() *segfetcher.Fetcher {
	return &segfetcher.Fetcher{
		Validator:     f.Validator,
		Splitter:      f.Splitter,
		Resolver:      f.Resolver,
		Requester:     f.Requester,
		ReplyHandler:  f.ReplyHandler,
		PathDB:        f.PathDB,
		QueryInterval: f.QueryInterval,
	}
}

func TestFetcher(t *testing.T) {
	rootCtrl := gomock.NewController(t)
	defer rootCtrl.Finish()
	tg := newTestGraph(rootCtrl)
	testErr := errors.New("Test err")

	tests := map[string]struct {
		PrepareFetcher func(*TestableFetcher)
		Request        segfetcher.Request
		ErrorAssertion require.ErrorAssertionFunc
		ExpectedSegs   segfetcher.Segments
	}{
		"Invalid request": {
			PrepareFetcher: func(f *TestableFetcher) {
				f.Validator.EXPECT().Validate(gomock.Any(), gomock.Any()).Return(testErr)
			},
			ErrorAssertion: require.Error,
		},
		"Splitter error": {
			PrepareFetcher: func(f *TestableFetcher) {
				f.Validator.EXPECT().Validate(gomock.Any(), gomock.Any())
				f.Splitter.EXPECT().Split(gomock.Any(), gomock.Any()).
					Return(segfetcher.RequestSet{}, testErr)
			},
			ErrorAssertion: require.Error,
		},
		"Resolver error": {
			PrepareFetcher: func(f *TestableFetcher) {
				f.Validator.EXPECT().Validate(gomock.Any(), gomock.Any())
				f.Splitter.EXPECT().Split(gomock.Any(), gomock.Any())
				f.Resolver.EXPECT().Resolve(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(segfetcher.Segments{}, segfetcher.RequestSet{}, testErr)
			},
			ErrorAssertion: require.Error,
		},
		"Immediately resolved": {
			PrepareFetcher: func(f *TestableFetcher) {
				f.Validator.EXPECT().Validate(gomock.Any(), gomock.Any())
				reqSet := segfetcher.RequestSet{
					Up: segfetcher.Request{Src: non_core_111, Dst: core_130},
				}
				f.Splitter.EXPECT().Split(gomock.Any(), gomock.Any()).
					Return(reqSet, nil)
				f.Resolver.EXPECT().Resolve(gomock.Any(), gomock.Any(), gomock.Eq(reqSet)).
					Return(segfetcher.Segments{Up: seg.Segments{tg.seg130_111}},
						segfetcher.RequestSet{}, nil)
			},
			ErrorAssertion: require.NoError,
			ExpectedSegs:   segfetcher.Segments{Up: seg.Segments{tg.seg130_111}},
		},
		// XXX(lukedirtwalker): testing the full loop is quite involved, and is
		// therefore currently omitted.
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()
			f := NewTestFetcher(ctrl)
			test.PrepareFetcher(f)
			segs, err := f.Fetcher().FetchSegs(ctx, test.Request)
			test.ErrorAssertion(t, err)
			assert.Equal(t, test.ExpectedSegs, segs)
		})
	}
}
