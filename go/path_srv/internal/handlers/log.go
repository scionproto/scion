// Copyright 2018 ETH Zurich
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

package handlers

import (
	"net"
	"strings"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
)

func logSegRecs(logger log.Logger, prefix string, src net.Addr, segRecs *path_mgmt.SegRecs) {
	logger.Debug(prefix+" Received SegRecs", "src", src, "segs", getSegRecsString(segRecs))
}

func getSegRecsString(segRecs *path_mgmt.SegRecs) string {
	var lines []string
	lines = append(lines, getSegRecordStrings(segRecs.Recs)...)
	lines = append(lines, "revocations=")
	lines = append(lines, getRevocationStrings(segRecs.SRevInfos)...)
	return strings.Join(lines, "\n")
}

func getSegRecordStrings(records []*seg.Meta) []string {
	strs := make([]string, len(records))
	for i, segMeta := range records {
		strs[i] = segMeta.Segment.String()
	}
	return strs
}

func getRevocationStrings(revocations []*path_mgmt.SignedRevInfo) []string {
	strs := make([]string, len(revocations))
	for i, rev := range revocations {
		strs[i] = rev.String()
	}
	return strs
}
