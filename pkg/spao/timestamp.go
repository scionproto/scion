// Copyright 2022 ETH Zurich
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

package spao

import (
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
)

// RelativeTimestamp computes the relative timestamp (spaoTS) where:
// now = ts+spaoTS⋅𝑞, (where q := 6 ms and ts =  info[0].Timestamp, i.e.,
// the timestamp field in the first InfoField).
func RelativeTimestamp(ts uint32, now time.Time) (uint32, error) {
	timestamp := now.Sub(util.SecsToTime(ts)).Milliseconds() / 6
	if timestamp >= (1 << 24) {
		return 0, serrors.New("relative timestamp is bigger than 2^24-1")
	}
	return uint32(timestamp), nil
}

// Time computes the time instant (then) where:
// then = ts + spaoTS⋅𝑞, (where q := 6 ms and ts =  info[0].Timestamp, i.e.,
// the timestamp field in the first InfoField).
func Time(ts uint32, spaoTS uint32) time.Time {
	return util.SecsToTime(ts).Add(time.Millisecond * time.Duration(spaoTS) * 6)
}
