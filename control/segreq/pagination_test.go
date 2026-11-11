// Copyright 2026 ETH Zurich
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

package segreq_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/control/segreq"
	seg "github.com/scionproto/scion/pkg/segment"
)

func TestPagination(t *testing.T) {
	type test struct {
		Name      string
		PageSize  int
		PageToken string
		GetPaths  func() []segreq.CombinedPath
		Evaluate  func([]*seg.PathSegment, []*seg.PathSegment, []*seg.PathSegment, string)
	}
	tests := []test{
		// single segment tests - up path segment
		{
			Name:      "SingleUpPathSegmentSinglePath",
			PageSize:  2,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 1)
				assert.Len(t, core, 0)
				assert.Len(t, down, 0)
				assert.Equal(t, "", nextPage)
			},
		},
		{
			Name:      "SingleUpPathSegmentManyPaths",
			PageSize:  2,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment: &seg.PathSegment{},
					},
					{
						UpSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 2)
				assert.Len(t, core, 0)
				assert.Len(t, down, 0)
				assert.Equal(t, "", nextPage)
			},
		},
		{
			Name:      "SingleUpPathSegmentManyPathsWithPaginationPage0",
			PageSize:  2,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment: &seg.PathSegment{},
					},
					{
						UpSegment: &seg.PathSegment{},
					},
					{
						UpSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 2)
				assert.Len(t, core, 0)
				assert.Len(t, down, 0)
				assert.Equal(t, "2", nextPage)
			},
		},
		{
			Name:      "SingleUpPathSegmentManyPathsWithPaginationPage1",
			PageSize:  2,
			PageToken: "2",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment: &seg.PathSegment{},
					},
					{
						UpSegment: &seg.PathSegment{},
					},
					{
						UpSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 1)
				assert.Len(t, core, 0)
				assert.Len(t, down, 0)
				assert.Equal(t, "", nextPage)
			},
		},
		// single segment tests - core path segment
		{
			Name:      "SingleCorePathSegmentSinglePath",
			PageSize:  2,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						CoreSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 0)
				assert.Len(t, core, 1)
				assert.Len(t, down, 0)
				assert.Equal(t, "", nextPage)
			},
		},
		{
			Name:      "SingleCorePathSegmentManyPaths",
			PageSize:  2,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						CoreSegment: &seg.PathSegment{},
					},
					{
						CoreSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 0)
				assert.Len(t, core, 2)
				assert.Len(t, down, 0)
				assert.Equal(t, "", nextPage)
			},
		},
		{
			Name:      "SingleCorePathSegmentManyPathsWithPaginationPage0",
			PageSize:  2,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						CoreSegment: &seg.PathSegment{},
					},
					{
						CoreSegment: &seg.PathSegment{},
					},
					{
						CoreSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 0)
				assert.Len(t, core, 2)
				assert.Len(t, down, 0)
				assert.Equal(t, "2", nextPage)
			},
		},
		{
			Name:      "SingleCorePathSegmentManyPathsWithPaginationPage1",
			PageSize:  2,
			PageToken: "2",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						CoreSegment: &seg.PathSegment{},
					},
					{
						CoreSegment: &seg.PathSegment{},
					},
					{
						CoreSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 0)
				assert.Len(t, core, 1)
				assert.Len(t, down, 0)
				assert.Equal(t, "", nextPage)
			},
		},
		// single segment tests - down path segment
		{
			Name:      "SingleDownPathSegmentSinglePath",
			PageSize:  2,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						DownSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 0)
				assert.Len(t, core, 0)
				assert.Len(t, down, 1)
				assert.Equal(t, "", nextPage)
			},
		},
		{
			Name:      "SingleDownPathSegmentManyPaths",
			PageSize:  2,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						DownSegment: &seg.PathSegment{},
					},
					{
						DownSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 0)
				assert.Len(t, core, 0)
				assert.Len(t, down, 2)
				assert.Equal(t, "", nextPage)
			},
		},
		{
			Name:      "SingleDownPathSegmentManyPathsWithPaginationPage0",
			PageSize:  2,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						DownSegment: &seg.PathSegment{},
					},
					{
						DownSegment: &seg.PathSegment{},
					},
					{
						DownSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 0)
				assert.Len(t, core, 0)
				assert.Len(t, down, 2)
				assert.Equal(t, "2", nextPage)
			},
		},
		{
			Name:      "SingleDownPathSegmentManyPathsWithPaginationPage1",
			PageSize:  2,
			PageToken: "2",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						DownSegment: &seg.PathSegment{},
					},
					{
						DownSegment: &seg.PathSegment{},
					},
					{
						DownSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 0)
				assert.Len(t, core, 0)
				assert.Len(t, down, 1)
				assert.Equal(t, "", nextPage)
			},
		},
		// paths consisting of two segments
		{
			Name:      "TwoPathSegmentsSize2Page0",
			PageSize:  2,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 1)
				assert.Len(t, core, 1)
				assert.Len(t, down, 0)
				assert.Equal(t, "1", nextPage)
			},
		},
		{
			Name:      "TwoPathSegmentsSize2Page1",
			PageSize:  2,
			PageToken: "1",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 1)
				assert.Len(t, core, 1)
				assert.Len(t, down, 0)
				assert.Equal(t, "2", nextPage)
			},
		},
		{
			Name:      "TwoPathSegmentsSize2Page2",
			PageSize:  2,
			PageToken: "2",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 1)
				assert.Len(t, core, 1)
				assert.Len(t, down, 0)
				assert.Equal(t, "", nextPage)
			},
		},
		{
			Name:      "TwoPathSegmentsSize3Page0",
			PageSize:  3,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 2)
				assert.Len(t, core, 1)
				assert.Len(t, down, 0)
				assert.Equal(t, "1", nextPage)
			},
		},
		{
			Name:      "TwoPathSegmentsSize3Page1",
			PageSize:  3,
			PageToken: "1",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 2)
				assert.Len(t, core, 1)
				assert.Len(t, down, 0)
				assert.Equal(t, "2", nextPage)
			},
		},
		{
			Name:      "TwoPathSegmentsSize3Page2",
			PageSize:  3,
			PageToken: "2",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 1)
				assert.Len(t, core, 1)
				assert.Len(t, down, 0)
				assert.Equal(t, "", nextPage)
			},
		},
		{
			Name:      "TwoPathSegmentsUpDown",
			PageSize:  3,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment:   &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 2)
				assert.Len(t, core, 0)
				assert.Len(t, down, 1)
				assert.Equal(t, "1", nextPage)
			},
		},
		// 3 path segment tests
		{
			Name:      "ThreePathSegmentsPage0",
			PageSize:  6,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 2)
				assert.Len(t, core, 2)
				assert.Len(t, down, 2)
				assert.Equal(t, "2", nextPage)
			},
		},
		{
			Name:      "ThreePathSegmentsPage1",
			PageSize:  6,
			PageToken: "2",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 2)
				assert.Len(t, core, 2)
				assert.Len(t, down, 2)
				assert.Equal(t, "", nextPage)
			},
		},
		{
			Name:      "ThreePathSegmentsSize7Page0",
			PageSize:  7,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 3)
				assert.Len(t, core, 2)
				assert.Len(t, down, 2)
				assert.Equal(t, "2", nextPage)
			},
		},
		{
			Name:      "ThreePathSegmentsSize7Page1",
			PageSize:  7,
			PageToken: "2",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 2)
				assert.Len(t, core, 2)
				assert.Len(t, down, 2)
				assert.Equal(t, "", nextPage)
			},
		},
		// now mix paths of different number of segments
		{
			Name:      "MixedSegmentsPage0",
			PageSize:  5,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment:   &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 2)
				assert.Len(t, core, 1)
				assert.Len(t, down, 2)
				assert.Equal(t, "2", nextPage)
			},
		},
		{
			Name:      "MixedSegmentsPage1",
			PageSize:  5,
			PageToken: "2",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment:   &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 2)
				assert.Len(t, core, 2)
				assert.Len(t, down, 1)
				assert.Equal(t, "3", nextPage)
			},
		},
		{
			Name:      "MixedSegmentsPage2",
			PageSize:  5,
			PageToken: "3",
			GetPaths: func() []segreq.CombinedPath {
				return []segreq.CombinedPath{
					{
						UpSegment:   &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
					{
						UpSegment:   &seg.PathSegment{},
						CoreSegment: &seg.PathSegment{},
						DownSegment: &seg.PathSegment{},
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 1)
				assert.Len(t, core, 1)
				assert.Len(t, down, 1)
				assert.Equal(t, "", nextPage)
			},
		},
		// now test for paths that share segments
		{
			Name:      "SharedSegmentsPage0",
			PageSize:  5,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				upSegment := &seg.PathSegment{}
				downSegment := &seg.PathSegment{}
				return []segreq.CombinedPath{
					{
						UpSegment:   upSegment,
						CoreSegment: &seg.PathSegment{},
						DownSegment: downSegment,
					},
					{
						UpSegment:   upSegment,
						CoreSegment: &seg.PathSegment{},
						DownSegment: downSegment,
					},
					{
						UpSegment:   upSegment,
						CoreSegment: &seg.PathSegment{},
						DownSegment: downSegment,
					},
					{
						UpSegment:   upSegment,
						CoreSegment: &seg.PathSegment{},
						DownSegment: downSegment,
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 1)
				assert.Len(t, core, 3)
				assert.Len(t, down, 1)
				assert.Equal(t, "3", nextPage)
			},
		},
		{
			Name:      "SharedSegmentsPage1",
			PageSize:  5,
			PageToken: "3",
			GetPaths: func() []segreq.CombinedPath {
				upSegment := &seg.PathSegment{}
				downSegment := &seg.PathSegment{}
				return []segreq.CombinedPath{
					{
						UpSegment:   upSegment,
						CoreSegment: &seg.PathSegment{},
						DownSegment: downSegment,
					},
					{
						UpSegment:   upSegment,
						CoreSegment: &seg.PathSegment{},
						DownSegment: downSegment,
					},
					{
						UpSegment:   upSegment,
						CoreSegment: &seg.PathSegment{},
						DownSegment: downSegment,
					},
					{
						UpSegment:   upSegment,
						CoreSegment: &seg.PathSegment{},
						DownSegment: downSegment,
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 1)
				assert.Len(t, core, 1)
				assert.Len(t, down, 1)
				assert.Equal(t, "", nextPage)
			},
		},
		{
			Name:      "SharedSegmentsSinglePage",
			PageSize:  5,
			PageToken: "",
			GetPaths: func() []segreq.CombinedPath {
				upSegment := &seg.PathSegment{}
				downSegment := &seg.PathSegment{}
				return []segreq.CombinedPath{
					{
						UpSegment:   upSegment,
						CoreSegment: &seg.PathSegment{},
						DownSegment: downSegment,
					},
					{
						UpSegment:   upSegment,
						CoreSegment: &seg.PathSegment{},
						DownSegment: downSegment,
					},
					{
						UpSegment:   upSegment,
						CoreSegment: &seg.PathSegment{},
						DownSegment: downSegment,
					},
				}
			},
			Evaluate: func(up, core, down []*seg.PathSegment, nextPage string) {
				assert.Len(t, up, 1)
				assert.Len(t, core, 3)
				assert.Len(t, down, 1)
				assert.Equal(t, "", nextPage)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			paginator := segreq.NewPaginator()
			paths := tc.GetPaths()
			up, core, down, nextPage := paginator.GetPage(paths, tc.PageSize, tc.PageToken)
			tc.Evaluate(up, core, down, nextPage)
		})
	}
}
