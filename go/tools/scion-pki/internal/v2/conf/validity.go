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

package conf

import (
	"time"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

// Validity defines a validity period.
type Validity struct {
	NotBefore uint32       `toml:"not_before"`
	Validity  util.DurWrap `toml:"validity"`
}

// Validate checks that the validity is set.
func (v Validity) Validate() error {
	if v.Validity.Duration == 0 {
		return serrors.New("validity period not set")
	}
	return nil
}

// Eval returns the validity period. The not before parameter is only used if
// the struct's not before field value is zero.
func (v Validity) Eval(notBefore time.Time) scrypto.Validity {
	if v.NotBefore != 0 {
		notBefore = util.SecsToTime(v.NotBefore)
	}
	return scrypto.Validity{
		NotBefore: util.UnixTime{Time: notBefore},
		NotAfter:  util.UnixTime{Time: notBefore.Add(v.Validity.Duration)},
	}
}
