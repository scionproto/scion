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
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
)

func logSegReg(logger log.Logger, prefix string, segReg *path_mgmt.SegReg) {
	logSegRecs(logger, prefix, segReg.SegRecs)
	for _, revocation := range segReg.SRevInfos {
		logger.Debug(prefix+"Received revocation", "rev", revocation.String())
	}
}

func logSegRecs(logger log.Logger, prefix string, segRecs *path_mgmt.SegRecs) {
	for _, segMeta := range segRecs.Recs {
		logger.Debug(prefix+"Received PCB", "seg", segMeta.Segment.String())
	}
}
