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

package sig_mgmt

import (
	"encoding/json"
	"fmt"
)

type SessionType uint8

func (st SessionType) String() string {
	return fmt.Sprintf("0x%02x", uint8(st))
}

func (st SessionType) MarshalJSON() ([]byte, error) {
	// Stop JSON from converting []SessionType to a string
	return json.Marshal(int(st))
}
