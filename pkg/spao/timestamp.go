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

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// RelativeTimestamp returns the relative timestamp (RelTime) as the time diference from
// time instant t to the beginning of the drkey epoch.
func RelativeTimestamp(e drkey.Epoch, t time.Time) (uint64, error) {
	relTime := t.Sub(e.NotBefore).Nanoseconds()
	if relTime >= (1 << 48) {
		return 0, serrors.New("relative timestamp is bigger than 2^48-1")
	}
	return uint64(relTime), nil
}

// AbsoluteTimestamp returns the absolute timestamp (AbsTime) based on the
// relTime (Timestamp / Sequence Number field in SPAO header) and the DRKey
// information.
func AbsoluteTimestamp(e drkey.Epoch, relTime uint64) time.Time {
	return e.NotBefore.Add(time.Duration(relTime))
}
