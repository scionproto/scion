// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package util

import (
	"time"

	"github.com/scionproto/scion/go/lib/common"
)

// SecsToTime takes seconds stored in a uint32.
func SecsToTime(t uint32) time.Time {
	return time.Unix(int64(t), 0)
}

// TimeToSecs returns seconds stored as uint32.
func TimeToSecs(t time.Time) uint32 {
	return uint32(t.Unix())
}

// TimeToString formats the time as a string.
func TimeToString(t time.Time) string {
	return t.UTC().Format(common.TimeFmt)
}

// SecsToCompact creates a compact string representation from the seconds.
func SecsToCompact(t uint32) string {
	return TimeToCompact(SecsToTime(t))
}

// TimeToCompact formats the time as a compat string, e.g. it discards the
// milliseconds parts if the time only has second resolution.
func TimeToCompact(t time.Time) string {
	if t.Nanosecond() == 0 {
		return t.UTC().Format(common.TimeFmtSecs)
	}
	return TimeToString(t)
}
