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
	"strconv"
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

type Time time.Time

func (t Time) Time() time.Time {
	return time.Time(t)
}

func (t *Time) UnmarshalText(b []byte) error {
	unix, err := strconv.ParseUint(string(b), 10, 32)
	if err == nil {
		if unix == 0 {
			*t = Time{}
			return nil
		}
		*t = Time(util.SecsToTime(uint32(unix)))
		return nil
	}

	parsed, err := time.Parse(time.RFC3339, string(b))
	if err != nil {
		return serrors.Wrap("unable to parse time", err)
	}
	*t = Time(parsed)
	return nil
}

// Validity defines a validity period.
type Validity struct {
	NotBefore Time         `toml:"not_before"`
	NotAfter  Time         `toml:"not_after"`
	Validity  util.DurWrap `toml:"validity"`
}

// Validate checks that the validity is set.
func (v *Validity) Validate() error {
	if (v.Validity.Duration == 0) == (v.NotAfter.Time().IsZero()) {
		return serrors.New("exactly one of 'validity' or 'not_after' must be set")
	}
	return nil
}

// Eval returns the validity period. The not before parameter is only used if
// the struct's not before field value is zero.
func (v Validity) Eval(notBefore time.Time) cppki.Validity {
	if nb := time.Time(v.NotBefore); !nb.IsZero() {
		notBefore = nb
	}
	return cppki.Validity{
		NotBefore: notBefore,
		NotAfter: func() time.Time {
			if !v.NotAfter.Time().IsZero() {
				return v.NotAfter.Time()
			}
			return notBefore.Add(v.Validity.Duration)
		}(),
	}
}
