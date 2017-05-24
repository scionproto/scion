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

const (
	// HashTreeTTL is the TTL of one hash tree (in seconds).
	// FIXME(shitz): This should really be matching spath.MaxTTL, but more importantly,
	// it needs to match the hash tree ttl used by the BS, which is currently set to 30 mins.
	HashTreeTTL = 30 * 60 * time.Second

	// HashTreeEpochTime is the duration of one epoch (in seconds).
	HashTreeEpochTime = 10 * time.Second

	// HashTreeEpochTolerance is the duration after a revocation expired within which a
	// revocation is still accepted by a verifier.
	HashTreeEpochTolerance = 2 * time.Second
)

// GetCurrentHashTreeEpoch returns the current epoch ID.
func GetCurrentHashTreeEpoch() uint64 {
	return uint64(time.Now().Unix() / int64(HashTreeEpochTime.Seconds()))
}

// GetTimeSinceHashTreeEpoch returns the time since the start of epoch.
func GetTimeSinceHashTreeEpoch(epoch uint64) time.Duration {
	epochStart := time.Unix(0, int64(epoch)*HashTreeEpochTime.Nanoseconds())
	return time.Since(epochStart)
}

// VerifyHashTreeEpoch verifies a given hash tree epoch. An epoch is valid if it is
// equal to the current epoch or within the tolerance limit of the next epoch.
func VerifyHashTreeEpoch(epoch uint64) bool {
	return GetTimeSinceHashTreeEpoch(epoch) < (HashTreeEpochTime + HashTreeEpochTolerance)
}
