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

package scrypto

import (
	"strconv"
)

// LatestVer is the wildcard version indicating the highest available version
// when requesting certificate chains and TRCs.
const LatestVer Version = 0

// Version identifies the version of a trust file. It cannot be
// marshalled/unmarshalled to/from LatestVer.
type Version uint64

// IsLatest checks if the value is LatestVer
func (v Version) IsLatest() bool {
	return v == LatestVer
}

func (v Version) String() string {
	if v.IsLatest() {
		return "latest"
	}
	return strconv.FormatUint(uint64(v), 10)
}
