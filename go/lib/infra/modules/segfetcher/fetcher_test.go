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

	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher/mock_segfetcher"
	"github.com/scionproto/scion/go/lib/pathdb/mock_pathdb"
)

type TestableFetcher struct {
	Resolver      *mock_segfetcher.MockResolver
	Requester     *mock_segfetcher.MockRequester
	ReplyHandler  *mock_segfetcher.MockReplyHandler
	PathDB        *mock_pathdb.MockPathDB
	QueryInterval time.Duration
}

func NewTestFetcher(ctrl *gomock.Controller) *TestableFetcher {
	return &TestableFetcher{
		Resolver:      mock_segfetcher.NewMockResolver(ctrl),
		Requester:     mock_segfetcher.NewMockRequester(ctrl),
		ReplyHandler:  mock_segfetcher.NewMockReplyHandler(ctrl),
		PathDB:        mock_pathdb.NewMockPathDB(ctrl),
		QueryInterval: time.Minute,
	}
}

func (f *TestableFetcher) Fetcher() *segfetcher.Fetcher {
	return &segfetcher.Fetcher{
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
		Requests       segfetcher.Requests
		ErrorAssertion require.ErrorAssertionFunc
		ExpectedSegs   segfetcher.Segments
	}{
		"Resolver error": {
			PrepareFetcher: func(f *TestableFetcher) {
				f.Resolver.EXPECT().Resolve(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(segfetcher.Segments{}, segfetcher.Requests{}, testErr)
			},
			ErrorAssertion: require.Error,
			ExpectedSegs:   segfetcher.Segments{},
		},
		"Immediately resolved": {
			Requests: segfetcher.Requests{
				segfetcher.Request{SegType: Up, Src: non_core_111, Dst: core_130},
			},
			PrepareFetcher: func(f *TestableFetcher) {
				f.Resolver.EXPECT().Resolve(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(segfetcher.Segments{tg.seg130_111_up},
						segfetcher.Requests{}, nil)
			},
			ErrorAssertion: require.NoError,
			ExpectedSegs:   segfetcher.Segments{tg.seg130_111_up},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()
			f := NewTestFetcher(ctrl)
			test.PrepareFetcher(f)
			segs, err := f.Fetcher().Fetch(ctx, test.Requests, false)
			test.ErrorAssertion(t, err)
			assert.Equal(t, test.ExpectedSegs, segs)
		})
	}
}
