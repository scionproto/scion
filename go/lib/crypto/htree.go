// Copyright 2017 ETH Zurich
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

package crypto

import (
	"time"
)

// HashTreeTTL is the TTL of one hash tree (in seconds).
// FIXME(shitz): This should really be matching spath.MaxTTL, but more importantely,
// it needs to match the hash tree ttl used by the BS, which is currently set to 30 mins.
const HashTreeTTL = 30 * 60

// HashTreeEpochTime is the duration of one epoch (in seconds).
const HashTreeEpochTime = 10

func GetCurrentEpoch() uint16 {
	window := time.Now().Unix() % HashTreeTTL
	return uint16(window / HashTreeEpochTime)
}
