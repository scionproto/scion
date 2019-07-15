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
	"fmt"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
)

// Validity indicates a validity period.
type Validity struct {
	NotBefore util.UnixTime `json:"NotBefore"`
	NotAfter  util.UnixTime `json:"NotAfter"`
}

type validity struct {
	NotBefore *util.UnixTime `json:"NotBefore"`
	NotAfter  *util.UnixTime `json:"NotAfter"`
}

// UnmarshalJSON checks that both NotBefore and NotAfter are set.
func (v *Validity) UnmarshalJSON(b []byte) error {
	var p validity
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	if p.NotBefore == nil {
		return common.NewBasicError("NotBefore unset", nil)
	}
	if p.NotAfter == nil {
		return common.NewBasicError("NotBefore unset", nil)
	}
	*v = Validity{
		NotBefore: *p.NotBefore,
		NotAfter:  *p.NotAfter,
	}
	return nil
}

// Contains indicates whether the provided time is inside the validity period.
func (v *Validity) Contains(t time.Time) bool {
	return !t.Before(v.NotBefore.Time) && !t.After(v.NotAfter.Time)
}

func (v *Validity) String() string {
	return fmt.Sprintf("[%s, %s]", v.NotBefore, v.NotAfter)
}
