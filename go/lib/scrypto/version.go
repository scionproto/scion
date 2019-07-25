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
	"encoding/json"
	"errors"
	"strconv"
)

// ErrInvalidVersion indicates an invalid trust file version.
var ErrInvalidVersion = errors.New("version must not be zero")

var _ json.Unmarshaler = (*Version)(nil)
var _ json.Marshaler = (*Version)(nil)

// Version identifies the version of a trust file. It cannot be
// marshalled/unmarshalled to/from LatestVer.
type Version uint64

// UnmarshalJSON checks that the value is not LatestVer.
func (v *Version) UnmarshalJSON(b []byte) error {
	parsed, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil {
		return err
	}
	if parsed == LatestVer {
		return ErrInvalidVersion
	}
	*v = Version(parsed)
	return nil
}

// MarshalJSON checks that the value is not LatestVer.
func (v Version) MarshalJSON() ([]byte, error) {
	if uint64(v) == LatestVer {
		return nil, ErrInvalidVersion
	}
	return json.Marshal(uint64(v))
}
