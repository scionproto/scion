// Copyright 2021 Anapaya Systems
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

package flag

import (
	"strconv"
	"time"

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

// Time implements pflags.Value.
//
// The flag value can be one of the following:
// - RFC3339 timestamp
// - unix timestamp
// - relative time duration
//
// For relative time duration, the same formats as util.ParseDuration are
// supported.
//
// The default value returned by the String() method is calculated as
// Time.Sub(Current), unless Default is set. If Default is set, that is
// returned as the default value.
//
// Either Time or Default must be set. If neither is set, this flag panics when
// constructing the default value.
type Time struct {
	// Time indicates the time after the flag is parsed.
	Time time.Time
	// Current indicates the current time for relative time duration.
	Current time.Time
	// Default is a custom default string.
	Default string
}

func (t *Time) Set(input string) error {
	parsed, err := time.Parse(time.RFC3339, input)
	if err == nil {
		t.Time = parsed.UTC()
		return nil
	}
	duration, err := util.ParseDuration(input)
	if err == nil {
		if t.Current.IsZero() {
			t.Current = time.Now().UTC()
		}
		t.Time = t.Current.Add(duration).UTC()
		return nil
	}
	ts, err := strconv.ParseInt(input, 10, 64)
	if err == nil {
		t.Time = time.Unix(ts, 0)
		return nil
	}
	return serrors.New("unsupported time format")
}

func (t *Time) UnmarshalText(b []byte) error {
	return t.Set(string(b))
}

func (t *Time) Type() string {
	return "time"
}

func (t *Time) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t *Time) String() string {
	if t.Default != "" {
		return t.Default
	}
	if t.Time.IsZero() {
		panic("either Default or Time must be set")
	}
	return util.FmtDuration(t.Time.Sub(t.Current))
}
