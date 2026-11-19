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

package segreq

import (
	"strconv"

	seg "github.com/scionproto/scion/pkg/segment"
)

type Paginator struct {
}

func NewPaginator() *Paginator {
	return &Paginator{}
}

// GetPage takes a sorted slice of combined paths, the page size and page token.
// Default pageToken is "" or "0".
// Returns in total 'pageSize' up-path, core-path and down-path segments if the number of unique
// segments is >= 'pageSize'. If the number of unique segments is > 'pageSize', a pageToken
// corresponding to the next page is returned. A pageToken of "" implies that we have reached
// the end.
// For each page, including the final page, it is guaranteed to contain the segments to construct
// at least 1 full path.
// Within a page, all path segments are unique. Path segments may repeat over different pages.
func (p *Paginator) GetPage(paths []CombinedPath, pageSize int, pageToken string) (
	[]*seg.PathSegment, []*seg.PathSegment, []*seg.PathSegment, string) {

	pagination, err := strconv.Atoi(pageToken)
	if err != nil {
		pagination = 0
	}
	up := []*seg.PathSegment{}
	core := []*seg.PathSegment{}
	down := []*seg.PathSegment{}

	target := pageSize / 3
	upCount, coreCount, downCount := 0, 0, 0
	used := make(map[*seg.PathSegment]struct{})

	start := pagination
	i := start
	for ; i < len(paths); i++ {
		p := paths[i]
		if upCount+coreCount+downCount >= pageSize {
			break
		}

		score := 0

		if p.UpSegment != nil {
			if _, ok := used[p.UpSegment]; !ok {
				if upCount < target {
					score++
				}
			}
		}
		if p.CoreSegment != nil {
			if _, ok := used[p.CoreSegment]; !ok {
				if coreCount < target {
					score++
				}
			}
		}
		if p.DownSegment != nil {
			if _, ok := used[p.DownSegment]; !ok {
				if downCount < target {
					score++
				}
			}
		}

		// Skip path if it cannot contribute new path segments for each types target amount
		if score == 0 {
			continue
		}

		add := func(s *seg.PathSegment, typ int) {
			if s == nil {
				return
			}
			if _, ok := used[s]; ok {
				return
			}

			used[s] = struct{}{}

			switch typ {
			case 0:
				up = append(up, s)
				upCount++
			case 1:
				core = append(core, s)
				coreCount++
			case 2:
				down = append(down, s)
				downCount++
			}
		}

		// Prefer adding segments that help balance first
		if p.UpSegment != nil && upCount < target {
			add(p.UpSegment, 0)
		}
		if p.CoreSegment != nil && coreCount < target {
			add(p.CoreSegment, 1)
		}
		if p.DownSegment != nil && downCount < target {
			add(p.DownSegment, 2)
		}
	}
	partialPath := false
	// We have now included the path segments for at least the paths paths[start : start+target].
	// Now fill up the page with segments of additional paths.
	for i = start + target; i < len(paths); i++ {
		p := paths[i]
		if upCount+coreCount+downCount >= pageSize {
			break
		}

		tryAdd := func(s *seg.PathSegment, typ int) bool {
			if s == nil {
				return false
			}
			if _, ok := used[s]; ok {
				return true
			}
			if upCount+coreCount+downCount >= pageSize {
				return false
			}
			used[s] = struct{}{}

			switch typ {
			case 0:
				up = append(up, s)
				upCount++
			case 1:
				core = append(core, s)
				coreCount++
			case 2:
				down = append(down, s)
				downCount++
			}
			return true
		}

		if p.UpSegment != nil {
			tryAdd(p.UpSegment, 0)
		}
		if p.CoreSegment != nil {
			if !tryAdd(p.CoreSegment, 1) {
				partialPath = true
				break
			}
		}
		if p.DownSegment != nil {
			if !tryAdd(p.DownSegment, 2) {
				partialPath = true
				break
			}
		}
	}
	if len(up)+len(core)+len(down) < pageSize || (i == len(paths) && !partialPath) {
		// we have reached the last page (i.e. together with the current page,
		// the endhost should have received all path segments)
		return up, core, down, ""
	}
	return up, core, down, strconv.Itoa(i)
}
